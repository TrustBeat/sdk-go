// Command smoke drives the TrustBeat Go SDK against a LIVE API.
//
// Driven by tests/e2e/sdk_smoke.py (the orchestrator), not run directly in CI.
// Two commands:
//
//	submit          anchor TB_HASH, print the tracking id on stdout
//	verify <id>     fetch the proof via the SDK, check the contract, verify locally
//
// Env:
//
//	TB_BASE_URL     API base URL (e.g. http://localhost:8080/v1)
//	TB_API_KEY      provisioned account API key
//	TB_HASH         SHA-256 hex the SDK anchors / echoes back
//
// Exit 0 on success, non-zero on any failure.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	tb "github.com/TrustBeat/sdk-go"
)

// aiMeta is the fixed AI-decision metadata — only the hashes vary per run.
func aiMeta() *tb.AiDecisionMetadata {
	return &tb.AiDecisionMetadata{
		ModelID:        "claude-opus-4-8",
		SystemName:     "trustbeat-sdk-smoke",
		RiskCategory:   "employment",
		DecisionType:   "classification",
		HumanOversight: true,
		TimeEnvelope: tb.AiTimeEnvelope{
			StartedAt:   "2026-06-29T10:00:00Z",
			CompletedAt: "2026-06-29T10:00:01Z",
		},
	}
}

func batchHashes() []string {
	seed := os.Getenv("TB_BATCH_SEED")
	n, _ := strconv.Atoi(os.Getenv("TB_BATCH_N"))
	out := make([]string, n)
	for i := 0; i < n; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s::%d", seed, i)))
		out[i] = hex.EncodeToString(sum[:])
	}
	return out
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func client() *tb.Client {
	base := os.Getenv("TB_BASE_URL")
	key := os.Getenv("TB_API_KEY")
	c, err := tb.NewClient(key, tb.WithBaseURL(base))
	if err != nil {
		fail("client: %v", err)
	}
	return c
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: smoke {submit|verify <id>}")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	switch os.Args[1] {
	case "submit":
		h := os.Getenv("TB_HASH")
		job, err := client().Anchor(ctx, h, nil)
		if err != nil {
			fail("submit: %v", err)
		}
		if job.ID == "" {
			fail("submit: empty tracking id")
		}
		fmt.Println(job.ID)

	case "verify":
		if len(os.Args) < 3 {
			fail("usage: smoke verify <id>")
		}
		id := os.Args[2]
		expected := os.Getenv("TB_HASH")
		c := client()

		proof, err := c.GetProof(ctx, id)
		if err != nil {
			fail("verify: %v", err)
		}
		if proof == nil {
			fail("verify: proof for %s not ready", id)
		}
		// Contract checks — what mocks never exercise.
		if expected != "" && !strings.EqualFold(proof.Hash, expected) {
			fail("verify: hash echo mismatch %s != %s", proof.Hash, expected)
		}
		if proof.MerkleRoot == "" {
			fail("verify: empty merkle_root")
		}
		if len(proof.Token) == 0 {
			fail("verify: empty token")
		}
		// Offline Merkle verification through the SDK.
		ok, err := c.Verify(proof)
		if err != nil {
			fail("verify: %v", err)
		}
		if !ok {
			fail("verify: local Merkle verification failed")
		}
		fmt.Printf("OK id=%s root=%.16s… token=%dB\n", id, proof.MerkleRoot, len(proof.Token))

	case "submit-batch":
		hashes := batchHashes()
		sub, err := client().AnchorBatch(ctx, hashes, nil)
		if err != nil {
			fail("submit-batch: %v", err)
		}
		if sub.SubmissionID == "" {
			fail("submit-batch: empty submission_id")
		}
		if len(sub.Items) != len(hashes) {
			fail("submit-batch: accepted %d != %d", len(sub.Items), len(hashes))
		}
		fmt.Println(sub.SubmissionID)

	case "verify-batch":
		if len(os.Args) < 3 {
			fail("usage: smoke verify-batch <id>")
		}
		sid := os.Args[2]
		expected := map[string]bool{}
		for _, h := range batchHashes() {
			expected[strings.ToLower(h)] = true
		}
		c := client()
		proofs, err := c.GetBatchProofs(ctx, sid)
		if err != nil {
			fail("verify-batch: %v", err)
		}
		if len(proofs) != len(expected) {
			fail("verify-batch: got %d proofs, want %d", len(proofs), len(expected))
		}
		for _, p := range proofs {
			if !expected[strings.ToLower(p.Hash)] {
				fail("verify-batch: unexpected proof hash %s", p.Hash)
			}
			if p.MerkleRoot == "" || len(p.Token) == 0 {
				fail("verify-batch: empty merkle_root/token for %s", p.ID)
			}
			ok, err := c.Verify(p)
			if err != nil {
				fail("verify-batch: %v", err)
			}
			if !ok {
				fail("verify-batch: local Merkle verification failed for %s", p.ID)
			}
		}
		fmt.Printf("OK batch sid=%s n=%d\n", sid, len(proofs))

	case "submit-ai":
		job, err := client().AnchorAiDecision(ctx, os.Getenv("TB_AI_INPUT"), os.Getenv("TB_AI_OUTPUT"), aiMeta(), nil)
		if err != nil {
			fail("submit-ai: %v", err)
		}
		if job.ID == "" {
			fail("submit-ai: empty tracking id")
		}
		fmt.Println(job.ID)

	case "verify-ai":
		if len(os.Args) < 3 {
			fail("usage: smoke verify-ai <id>")
		}
		id := os.Args[2]
		inHash, outHash := os.Getenv("TB_AI_INPUT"), os.Getenv("TB_AI_OUTPUT")
		c := client()
		proof, err := c.GetAiDecisionProof(ctx, id)
		if err != nil {
			fail("verify-ai: %v", err)
		}
		if proof == nil {
			fail("verify-ai: proof for %s not ready", id)
		}
		if !strings.EqualFold(proof.InputHash, inHash) {
			fail("verify-ai: input_hash echo mismatch %s != %s", proof.InputHash, inHash)
		}
		if !strings.EqualFold(proof.OutputHash, outHash) {
			fail("verify-ai: output_hash echo mismatch %s != %s", proof.OutputHash, outHash)
		}
		if proof.VerificationStatus != "VERIFIED" {
			fail("verify-ai: status %s != VERIFIED", proof.VerificationStatus)
		}
		if proof.Proof == nil {
			fail("verify-ai: missing Merkle proof")
		}
		ok, err := c.Verify(proof.Proof)
		if err != nil {
			fail("verify-ai: %v", err)
		}
		if !ok {
			fail("verify-ai: local Merkle verification failed")
		}
		fmt.Printf("OK ai id=%s combined=%.16s…\n", id, proof.CombinedHash)

	case "submit-file":
		job, err := client().AnchorFile(ctx, os.Getenv("TB_FILE_PATH"), nil)
		if err != nil {
			fail("submit-file: %v", err)
		}
		if job.ID == "" {
			fail("submit-file: empty tracking id")
		}
		fmt.Println(job.ID)

	case "submit-audit":
		eventID, err := client().SubmitAuditEvent(ctx,
			os.Getenv("TB_AUDIT_CATEGORY"), os.Getenv("TB_AUDIT_ACTOR"),
			os.Getenv("TB_AUDIT_ACTION"), os.Getenv("TB_AUDIT_TS"), nil)
		if err != nil {
			fail("submit-audit: %v", err)
		}
		if eventID == "" {
			fail("submit-audit: empty event_id")
		}
		fmt.Println(eventID)

	case "verify-audit":
		if len(os.Args) < 3 {
			fail("usage: smoke verify-audit <id>")
		}
		id := os.Args[2]
		c := client()
		proof, err := c.GetAuditEventProof(ctx, id)
		if err != nil {
			fail("verify-audit: %v", err)
		}
		if proof == nil {
			fail("verify-audit: proof for %s not ready", id)
		}
		if proof.EventID != id {
			fail("verify-audit: event_id echo mismatch %s != %s", proof.EventID, id)
		}
		if proof.CanonicalHash == "" {
			fail("verify-audit: empty canonical_hash")
		}
		if proof.BatchID == "" {
			fail("verify-audit: empty batch_id")
		}
		if proof.LeafIndex < 0 {
			fail("verify-audit: invalid leaf_index")
		}
		events, err := c.ListAuditEvents(ctx, url.Values{"trail_category": {os.Getenv("TB_AUDIT_CATEGORY")}})
		if err != nil {
			fail("verify-audit: %v", err)
		}
		found := false
		for _, e := range events {
			if e.EventID == id {
				found = true
				break
			}
		}
		if !found {
			fail("verify-audit: %s not returned by ListAuditEvents", id)
		}
		fmt.Printf("OK audit id=%s batch=%.12s… leaf=%d\n", id, proof.BatchID, proof.LeafIndex)

	case "verify-sig":
		doc, err := os.ReadFile(os.Getenv("TB_SIG_DOC"))
		if err != nil {
			fail("verify-sig: %v", err)
		}
		expected := os.Getenv("TB_SIG_DOCHASH")
		report, err := client().VerifySignature(ctx, doc, os.Getenv("TB_SIG_FORMAT"))
		if err != nil {
			fail("verify-sig: %v", err)
		}
		if !strings.EqualFold(report.DocumentHash, expected) {
			fail("verify-sig: document_hash mismatch %s != %s", report.DocumentHash, expected)
		}
		if report.Verdict == "" {
			fail("verify-sig: empty verdict")
		}
		if len(report.Signatures) == 0 {
			fail("verify-sig: report has no signatures")
		}
		fmt.Printf("OK sig verdict=%s signatures=%d\n", report.Verdict, len(report.Signatures))

	case "validate-cert":
		cert, err := os.ReadFile(os.Getenv("TB_CERT_PATH"))
		if err != nil {
			fail("validate-cert: %v", err)
		}
		res, err := client().ValidateCertificate(ctx, cert)
		if err != nil {
			fail("validate-cert: %v", err)
		}
		if res.Subject == "" {
			fail("validate-cert: empty subject")
		}
		if res.Issuer == "" {
			fail("validate-cert: empty issuer")
		}
		if res.ValidatedAt == "" {
			fail("validate-cert: empty validated_at")
		}
		fmt.Printf("OK cert subject=%.24s… qualified=%t\n", res.Subject, res.Qualified)

	default:
		fail("unknown command: %s", os.Args[1])
	}
}
