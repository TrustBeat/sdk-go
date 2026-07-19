package trustbeat_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TrustBeat/sdk-go"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

func anchorAcceptedJSON(id string) string {
	return fmt.Sprintf(`{"id":%q,"hash":"%s","hash_algorithm":"sha256","status":"pending","submitted_at":"2026-01-01T00:00:00Z","overage":false}`,
		id, strings.Repeat("a", 64))
}

func proofJSON(id string) string {
	leaf := strings.Repeat("ab", 32)
	token := base64.StdEncoding.EncodeToString([]byte("DER_BYTES"))
	return fmt.Sprintf(`{"id":%q,"hash":%q,"hash_algorithm":"sha256","batch_id":"batch-1","leaf_index":0,"merkle_root":%q,"proof_path":[],"token":%q,"token_format":"rfc3161","tsa_serial":"42","provider":"sk-demo","anchored_at":"2026-01-01T00:10:00Z","client_ref":null,"description":null}`,
		id, leaf, leaf, token)
}

func pendingJSON(id string) string {
	return fmt.Sprintf(`{"id":%q,"hash":"%s","hash_algorithm":"sha256","status":"pending"}`,
		id, strings.Repeat("a", 64))
}

func errJSON(msg string) string {
	return fmt.Sprintf(`{"error":{"message":%q,"code":"ERROR"}}`, msg)
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(body)) //nolint:errcheck
}

func newClient(t *testing.T, srv *httptest.Server) *trustbeat.Client {
	t.Helper()
	c, err := trustbeat.NewClient("tb_live_test",
		trustbeat.WithBaseURL(srv.URL+"/v1"),
		trustbeat.WithTimeout(5*1e9)) // 5s
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ── NewClient ─────────────────────────────────────────────────────────────────

func TestNewClientEmptyKeyReturnsError(t *testing.T) {
	_, err := trustbeat.NewClient("")
	if err == nil {
		t.Fatal("expected error for empty apiKey")
	}
}

// ── Anchor ────────────────────────────────────────────────────────────────────

func TestAnchorReturnsJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/anchor" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 202, anchorAcceptedJSON("track-1"))
	}))
	defer srv.Close()

	job, err := newClient(t, srv).Anchor(context.Background(), strings.Repeat("a", 64), nil)
	if err != nil {
		t.Fatal(err)
	}
	if job.ID != "track-1" {
		t.Errorf("ID = %q; want track-1", job.ID)
	}
	if job.Status != "pending" {
		t.Errorf("Status = %q; want pending", job.Status)
	}
	if job.Overage {
		t.Error("Overage should be false")
	}
}

func TestAnchorSendsAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		writeJSON(w, 202, anchorAcceptedJSON("t"))
	}))
	defer srv.Close()

	c, _ := trustbeat.NewClient("tb_live_mykey", trustbeat.WithBaseURL(srv.URL+"/v1"))
	c.Anchor(context.Background(), strings.Repeat("a", 64), nil) //nolint:errcheck
	if gotAuth != "Bearer tb_live_mykey" {
		t.Errorf("Authorization = %q; want Bearer tb_live_mykey", gotAuth)
	}
}

func TestAnchorSendsHashInBody(t *testing.T) {
	hash := strings.Repeat("b", 64)
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		writeJSON(w, 202, anchorAcceptedJSON("t"))
	}))
	defer srv.Close()

	newClient(t, srv).Anchor(context.Background(), hash, nil) //nolint:errcheck
	if body["hash"] != hash {
		t.Errorf("body hash = %v; want %s", body["hash"], hash)
	}
	if body["hash_algorithm"] != "SHA-256" {
		t.Errorf("hash_algorithm = %v; want SHA-256", body["hash_algorithm"])
	}
}

func TestAnchorOptsForwarded(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		writeJSON(w, 202, anchorAcceptedJSON("t"))
	}))
	defer srv.Close()

	newClient(t, srv).Anchor(context.Background(), strings.Repeat("a", 64), &trustbeat.AnchorOptions{ //nolint:errcheck
		ClientRef:   "ref-1",
		Description: "my doc",
	})
	if body["client_ref"] != "ref-1" {
		t.Errorf("client_ref = %v; want ref-1", body["client_ref"])
	}
	if body["description"] != "my doc" {
		t.Errorf("description = %v; want 'my doc'", body["description"])
	}
}

// ── AnchorBatch ───────────────────────────────────────────────────────────────

func TestAnchorBatchReturnsBatchSubmission(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/anchor/batch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := `{"submission_id":"sub-abc","accepted":[` + anchorAcceptedJSON("t1") + "," + anchorAcceptedJSON("t2") + `],"total":2}`
		writeJSON(w, 202, resp)
	}))
	defer srv.Close()

	result, err := newClient(t, srv).AnchorBatch(context.Background(),
		[]string{strings.Repeat("a", 64), strings.Repeat("b", 64)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.SubmissionID != "sub-abc" {
		t.Errorf("SubmissionID = %q; want sub-abc", result.SubmissionID)
	}
	if len(result.Items) != 2 {
		t.Fatalf("got %d items; want 2", len(result.Items))
	}
	if result.Items[0].ID != "t1" || result.Items[1].ID != "t2" {
		t.Errorf("IDs = %s, %s; want t1, t2", result.Items[0].ID, result.Items[1].ID)
	}
}

func TestAnchorBatchEmptyReturnsEmptySubmission(t *testing.T) {
	c, _ := trustbeat.NewClient("tb_live_test")
	result, err := c.AnchorBatch(context.Background(), nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(result.Items) != 0 {
		t.Errorf("expected empty items; got %d", len(result.Items))
	}
}

func TestAnchorBatchOver100ReturnsError(t *testing.T) {
	c, _ := trustbeat.NewClient("tb_live_test")
	hashes := make([]string, 101)
	for i := range hashes {
		hashes[i] = strings.Repeat("a", 64)
	}
	_, err := c.AnchorBatch(context.Background(), hashes, nil)
	if err == nil {
		t.Fatal("expected error for > 100 hashes")
	}
}

// ── GetProof ──────────────────────────────────────────────────────────────────

func TestGetProofReturnsPendingAsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, pendingJSON("track-1"))
	}))
	defer srv.Close()

	proof, err := newClient(t, srv).GetProof(context.Background(), "track-1")
	if err != nil {
		t.Fatal(err)
	}
	if proof != nil {
		t.Error("expected nil proof for pending anchor")
	}
}

func TestGetProofReturnsProofWhenReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, proofJSON("track-1"))
	}))
	defer srv.Close()

	proof, err := newClient(t, srv).GetProof(context.Background(), "track-1")
	if err != nil {
		t.Fatal(err)
	}
	if proof == nil {
		t.Fatal("expected non-nil proof")
	}
	if proof.ID != "track-1" {
		t.Errorf("ID = %q; want track-1", proof.ID)
	}
	if proof.TokenFormat != "rfc3161" {
		t.Errorf("TokenFormat = %q; want rfc3161", proof.TokenFormat)
	}
	if string(proof.Token) != "DER_BYTES" {
		t.Errorf("Token = %q; want DER_BYTES", proof.Token)
	}
}

// ── AnchorWait ────────────────────────────────────────────────────────────────

func TestAnchorWaitPollsAndReturnsProof(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			writeJSON(w, 200, pendingJSON("track-1"))
		} else {
			writeJSON(w, 200, proofJSON("track-1"))
		}
	}))
	defer srv.Close()

	proof, err := newClient(t, srv).AnchorWait(context.Background(), "track-1", &trustbeat.WaitOptions{
		Timeout:      5 * time.Second,
		PollInterval: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proof.ID != "track-1" {
		t.Errorf("ID = %q; want track-1", proof.ID)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 polls, got %d", calls)
	}
}

// ── Verify ────────────────────────────────────────────────────────────────────

func TestVerifyValidSingleLeaf(t *testing.T) {
	// Single-leaf tree: root == leaf hash
	leaf := sha256.Sum256([]byte("hello"))
	proof := &trustbeat.AnchorProof{
		Hash:       hex.EncodeToString(leaf[:]),
		MerkleRoot: hex.EncodeToString(leaf[:]),
		ProofPath:  nil,
	}
	ok, err := trustbeat.Verify(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected valid proof")
	}
}

func TestVerifyTamperedRootReturnsFalse(t *testing.T) {
	leaf := sha256.Sum256([]byte("hello"))
	proof := &trustbeat.AnchorProof{
		Hash:       hex.EncodeToString(leaf[:]),
		MerkleRoot: strings.Repeat("ff", 32),
		ProofPath:  nil,
	}
	ok, err := trustbeat.Verify(proof)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("tampered root should not verify")
	}
}

func TestVerifyTwoLeafTree(t *testing.T) {
	// Build a 2-leaf tree: root = SHA-256(leaf0 || leaf1)
	leaf0 := sha256.Sum256([]byte("doc0"))
	leaf1 := sha256.Sum256([]byte("doc1"))
	combined := sha256.New()
	combined.Write(leaf0[:])
	combined.Write(leaf1[:])
	root := combined.Sum(nil)

	// Verify leaf0: sibling is leaf1 on the right
	proof := &trustbeat.AnchorProof{
		Hash:       hex.EncodeToString(leaf0[:]),
		MerkleRoot: hex.EncodeToString(root),
		ProofPath: []trustbeat.ProofStep{
			{Sibling: hex.EncodeToString(leaf1[:]), Side: "right"},
		},
	}
	ok, err := trustbeat.Verify(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected valid proof for leaf0 in 2-leaf tree")
	}
}

func TestVerifyMalformedLeafHashReturnsError(t *testing.T) {
	proof := &trustbeat.AnchorProof{
		Hash:       "not-hex",
		MerkleRoot: strings.Repeat("ab", 32),
	}
	_, err := trustbeat.Verify(proof)
	if err == nil {
		t.Fatal("expected error for malformed hash")
	}
	var verr *trustbeat.VerificationError
	if !errors.As(err, &verr) {
		t.Errorf("expected *VerificationError, got %T", err)
	}
}

func TestVerifyUnknownSideReturnsError(t *testing.T) {
	leaf := sha256.Sum256([]byte("x"))
	proof := &trustbeat.AnchorProof{
		Hash:       hex.EncodeToString(leaf[:]),
		MerkleRoot: strings.Repeat("ab", 32),
		ProofPath:  []trustbeat.ProofStep{{Sibling: strings.Repeat("cd", 32), Side: "up"}},
	}
	_, err := trustbeat.Verify(proof)
	if err == nil {
		t.Fatal("expected error for unknown side")
	}
}

// ── Static hash utilities ─────────────────────────────────────────────────────

func TestHashBytesReturns64CharHex(t *testing.T) {
	h := trustbeat.HashBytes([]byte("hello"))
	if len(h) != 64 {
		t.Errorf("len = %d; want 64", len(h))
	}
	for _, ch := range h {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			t.Errorf("non-hex char %q in hash", ch)
		}
	}
}

func TestHashStringMatchesHashBytes(t *testing.T) {
	if trustbeat.HashString("world") != trustbeat.HashBytes([]byte("world")) {
		t.Error("HashString and HashBytes disagree")
	}
}

func TestHashFileReturnsCorrectDigest(t *testing.T) {
	content := []byte("deterministic content 42")
	expected := trustbeat.HashBytes(content)

	f, err := os.CreateTemp("", "tb-go-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(content) //nolint:errcheck
	f.Close()

	got, err := trustbeat.HashFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Errorf("HashFile = %s; want %s", got, expected)
	}
}

// ── AnchorFile ────────────────────────────────────────────────────────────────

func TestAnchorFileDescriptionDefaultsToFilename(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		writeJSON(w, 202, anchorAcceptedJSON("t"))
	}))
	defer srv.Close()

	f, _ := os.CreateTemp("", "tb-go-*.txt")
	defer os.Remove(f.Name())
	f.Write([]byte("data"))
	f.Close()

	newClient(t, srv).AnchorFile(context.Background(), f.Name(), nil) //nolint:errcheck

	gotDesc, _ := body["description"].(string)
	if !strings.HasSuffix(gotDesc, ".txt") {
		t.Errorf("description = %q; expected filename ending in .txt", gotDesc)
	}
}

func TestAnchorFileCustomDescriptionOverridesFilename(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		writeJSON(w, 202, anchorAcceptedJSON("t"))
	}))
	defer srv.Close()

	f, _ := os.CreateTemp("", "tb-go-*.bin")
	defer os.Remove(f.Name())
	f.Write([]byte("data"))
	f.Close()

	newClient(t, srv).AnchorFile(context.Background(), f.Name(), &trustbeat.AnchorOptions{Description: "my-doc"}) //nolint:errcheck

	if body["description"] != "my-doc" {
		t.Errorf("description = %v; want my-doc", body["description"])
	}
}

func TestAnchorFileSendsCorrectHash(t *testing.T) {
	content := []byte("hello trustbeat from Go")
	expected := trustbeat.HashBytes(content)

	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		writeJSON(w, 202, anchorAcceptedJSON("t"))
	}))
	defer srv.Close()

	f, _ := os.CreateTemp("", "tb-go-hash-*.bin")
	defer os.Remove(f.Name())
	f.Write(content)
	f.Close()

	newClient(t, srv).AnchorFile(context.Background(), f.Name(), nil) //nolint:errcheck

	if body["hash"] != expected {
		t.Errorf("hash = %v; want %s", body["hash"], expected)
	}
}

// ── Error mapping ─────────────────────────────────────────────────────────────

func TestHTTP401ReturnsAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, errJSON("Bad key"))
	}))
	defer srv.Close()

	_, err := newClient(t, srv).Anchor(context.Background(), strings.Repeat("a", 64), nil)
	var authErr *trustbeat.AuthError
	if !errors.As(err, &authErr) {
		t.Errorf("expected *AuthError, got %T: %v", err, err)
	}
}

func TestHTTP404ReturnsNotFoundError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, errJSON("Not found"))
	}))
	defer srv.Close()

	_, err := newClient(t, srv).GetProof(context.Background(), "nonexistent")
	var nfe *trustbeat.NotFoundError
	if !errors.As(err, &nfe) {
		t.Errorf("expected *NotFoundError, got %T: %v", err, err)
	}
}

func TestHTTP429ReturnsRateLimitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 429, errJSON("Slow down"))
	}))
	defer srv.Close()

	_, err := newClient(t, srv).Anchor(context.Background(), strings.Repeat("a", 64), nil)
	var rle *trustbeat.RateLimitError
	if !errors.As(err, &rle) {
		t.Errorf("expected *RateLimitError, got %T: %v", err, err)
	}
}

func TestHTTP500ReturnsTrustBeatErrorWithStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 500, errJSON("Server error"))
	}))
	defer srv.Close()

	_, err := newClient(t, srv).Anchor(context.Background(), strings.Repeat("a", 64), nil)
	var tbe *trustbeat.TrustBeatError
	if !errors.As(err, &tbe) {
		t.Errorf("expected *TrustBeatError, got %T: %v", err, err)
	}
	if tbe.Status != 500 {
		t.Errorf("Status = %d; want 500", tbe.Status)
	}
}

// ── GetAiDecisionProof (pending) ────────────────────────────────────────────

func TestGetAiDecisionProofPendingReturnsNil(t *testing.T) {
	// Before anchoring the API returns 200 with verification_status "PENDING".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"id":"ai-1","input_hash":"","output_hash":"","combined_hash":"","metadata":{},"verification_status":"PENDING","anchored_at":null,"proof":null}`)
	}))
	defer srv.Close()

	proof, err := newClient(t, srv).GetAiDecisionProof(context.Background(), "ai-1")
	if err != nil {
		t.Fatal(err)
	}
	if proof != nil {
		t.Error("expected nil proof while verification_status is PENDING")
	}
}

// ── ExportAuditEvents (from/to required) ────────────────────────────────────

func TestExportAuditEventsRequiresFromTo(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeJSON(w, 202, `{"job_id":"job-1","status":"pending"}`)
	}))
	defer srv.Close()

	_, err := newClient(t, srv).ExportAuditEvents(context.Background(), map[string]string{"trail_category": "financial"})
	if err == nil {
		t.Fatal("expected error when from/to missing")
	}
	if called {
		t.Error("no HTTP request should be sent when from/to are missing")
	}
}

// ── Tamper-Evident Logs (NIS2) ──────────────────────────────────────────────

func logProofJSON(status string) string {
	proof := "null"
	if status == "VERIFIED" {
		proof = proofJSON("log-1")
	}
	anchored := `"2026-04-15T10:10:00Z"`
	if status == "PENDING" {
		anchored = "null"
	}
	return fmt.Sprintf(`{"id":"log-1","log_hash":"%s","combined_hash":"%s","metadata":{"log_source":{"uri":"/var/log/app.log","name":"App","size_bytes":2048},"source_identity":{"hostname":"host-1","service_name":"payments"},"time_envelope":{"start_at":"2026-04-15T00:00:00Z","end_at":"2026-04-15T23:59:59Z"}},"verification_status":"%s","archive_stamps_count":0,"anchored_at":%s,"proof":%s}`,
		strings.Repeat("a", 64), strings.Repeat("c", 64), status, anchored, proof)
}

func TestAnchorLogSendsBody(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSON(w, 202, fmt.Sprintf(`{"id":"log-1","log_hash":"%s","combined_hash":"%s","status":"pending","submitted_at":"2026-04-15T10:00:00Z","overage":false,"label":"lbl"}`,
			strings.Repeat("b", 64), strings.Repeat("c", 64)))
	}))
	defer srv.Close()

	meta := &trustbeat.LogMetadata{
		LogSource:      trustbeat.LogSource{URI: "/var/log/app.log", Name: "App", SizeBytes: 2048},
		SourceIdentity: trustbeat.LogSourceIdentity{Hostname: "host-1", ServiceName: "payments"},
		TimeEnvelope:   &trustbeat.LogTimeEnvelope{StartAt: "2026-04-15T00:00:00Z", EndAt: "2026-04-15T23:59:59Z"},
	}
	job, err := newClient(t, srv).AnchorLog(context.Background(), strings.Repeat("b", 64), meta, "lbl")
	if err != nil {
		t.Fatal(err)
	}
	if job.ID != "log-1" || job.Label != "lbl" {
		t.Errorf("job = %+v", job)
	}
	if body["log_hash"] != strings.Repeat("b", 64) {
		t.Errorf("log_hash = %v", body["log_hash"])
	}
	md := body["metadata"].(map[string]any)
	if md["log_source"].(map[string]any)["uri"] != "/var/log/app.log" {
		t.Errorf("uri = %v", md["log_source"])
	}
	if md["source_identity"].(map[string]any)["service_name"] != "payments" {
		t.Errorf("service_name = %v", md["source_identity"])
	}
	if md["time_envelope"].(map[string]any)["end_at"] != "2026-04-15T23:59:59Z" {
		t.Errorf("time_envelope = %v", md["time_envelope"])
	}
}

func TestGetLogProofVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, logProofJSON("VERIFIED"))
	}))
	defer srv.Close()
	proof, err := newClient(t, srv).GetLogProof(context.Background(), "log-1")
	if err != nil {
		t.Fatal(err)
	}
	if proof == nil || proof.VerificationStatus != "VERIFIED" {
		t.Fatalf("proof = %+v", proof)
	}
	if proof.Metadata.LogSource.URI != "/var/log/app.log" {
		t.Errorf("metadata uri = %q", proof.Metadata.LogSource.URI)
	}
	if proof.Proof == nil {
		t.Error("expected non-nil Merkle proof")
	}
}

func TestGetLogProofPendingReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, logProofJSON("PENDING"))
	}))
	defer srv.Close()
	proof, err := newClient(t, srv).GetLogProof(context.Background(), "log-1")
	if err != nil {
		t.Fatal(err)
	}
	if proof != nil {
		t.Error("expected nil while PENDING")
	}
}

func TestGetLogStatusAndList(t *testing.T) {
	srvS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"id":"log-1","status":"anchored","submitted_at":"2026-04-15T10:00:00Z","anchored_at":"2026-04-15T10:10:00Z"}`)
	}))
	defer srvS.Close()
	st, err := newClient(t, srvS).GetLogStatus(context.Background(), "log-1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "anchored" || st.AnchoredAt != "2026-04-15T10:10:00Z" {
		t.Errorf("status = %+v", st)
	}

	srvL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("status") != "anchored" {
			t.Errorf("missing status filter: %s", r.URL.RawQuery)
		}
		writeJSON(w, 200, fmt.Sprintf(`{"logs":[{"id":"log-1","log_hash":"%s","status":"anchored","submitted_at":"2026-04-15T10:00:00Z","log_source_uri":"/var/log/app.log","service_name":"payments","label":"x"}],"total":1}`, strings.Repeat("a", 64)))
	}))
	defer srvL.Close()
	logs, err := newClient(t, srvL).ListLogs(context.Background(), url.Values{"status": {"anchored"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].LogSourceURI != "/var/log/app.log" {
		t.Errorf("logs = %+v", logs)
	}
}

func TestExportLogReturnsBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"bundle_type":"trustbeat.log.proof","id":"log-1"}`)
	}))
	defer srv.Close()
	blob, err := newClient(t, srv).ExportLog(context.Background(), "log-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "trustbeat.log.proof") {
		t.Errorf("bundle = %s", blob)
	}
}

func TestExportAiDecisionReturnsBytes(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		writeJSON(w, 200, `{"bundle_type":"trustbeat.ai.proof","id":"dec-1"}`)
	}))
	defer srv.Close()
	blob, err := newClient(t, srv).ExportAiDecision(context.Background(), "dec-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "trustbeat.ai.proof") {
		t.Errorf("bundle = %s", blob)
	}
	if gotPath != "/v1/ai/decisions/dec-1/export" {
		t.Errorf("path = %s", gotPath)
	}
}

func TestExportVerificationReturnsBytes(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		writeJSON(w, 200, `{"bundle_type":"trustbeat.verification.proof","id":"ver-1"}`)
	}))
	defer srv.Close()
	blob, err := newClient(t, srv).ExportVerification(context.Background(), "ver-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "trustbeat.verification.proof") {
		t.Errorf("bundle = %s", blob)
	}
	if gotPath != "/v1/verify/ver-1/export" {
		t.Errorf("path = %s", gotPath)
	}
}

func TestSubmitAuditEventsSendsBareArray(t *testing.T) {
	var body []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSON(w, 202, `{"event_ids":["e1","e2"]}`)
	}))
	defer srv.Close()
	ids, err := newClient(t, srv).SubmitAuditEvents(context.Background(), []map[string]any{
		{"trail_category": "financial", "actor": "svc:pay", "action": "payment.approved", "ts": "2026-04-15T10:00:00Z"},
		{"trail_category": "financial", "actor": "svc:pay", "action": "payment.settled", "ts": "2026-04-15T10:00:05Z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 2 || body[0]["action"] != "payment.approved" {
		t.Errorf("body = %+v", body)
	}
	if len(ids) != 2 || ids[0] != "e1" {
		t.Errorf("ids = %v", ids)
	}
}
