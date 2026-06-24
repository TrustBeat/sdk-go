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
	"os"
	"strconv"
	"strings"
	"time"

	tb "trustbeat.eu/trustbeat"
)

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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	default:
		fail("unknown command: %s", os.Args[1])
	}
}
