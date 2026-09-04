package trustbeat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func sha(b []byte) []byte { d := sha256.Sum256(b); return d[:] }

func rfc6962AuditProof() *AuditEventProof {
	a := sha([]byte("audit-a"))
	b := sha([]byte("audit-b"))
	la := sha(append([]byte{0x00}, a...))
	lb := sha(append([]byte{0x00}, b...))
	root := sha(append(append([]byte{0x01}, la...), lb...))
	return &AuditEventProof{
		EventID:         "evt_1",
		CanonicalHash:   hex.EncodeToString(a),
		BatchID:         "batch_1",
		LeafIndex:       0,
		MerklePath:      []AuditProofStep{{Sibling: hex.EncodeToString(lb), Side: "right"}},
		AnchoredAt:      "2026-01-01T00:00:00Z",
		MerkleRoot:      hex.EncodeToString(root),
		TreeSize:        2,
		MerkleAlgorithm: RFC6962SHA256,
	}
}

func TestVerifyAuditEventAcceptsAValidRfc6962Proof(t *testing.T) {
	ok, err := VerifyAuditEvent(rfc6962AuditProof())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v, want true/nil", ok, err)
	}
}

func TestVerifyAuditEventRejectsATamperedRoot(t *testing.T) {
	p := rfc6962AuditProof()
	p.MerkleRoot = hex.EncodeToString(sha([]byte("wrong")))
	ok, err := VerifyAuditEvent(p)
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestVerifyAuditEventFoldsLegacyProofs(t *testing.T) {
	a := sha([]byte("audit-a"))
	b := sha([]byte("audit-b"))
	root := sha(append(append([]byte{}, a...), b...))
	p := &AuditEventProof{
		CanonicalHash:   hex.EncodeToString(a),
		MerklePath:      []AuditProofStep{{Sibling: hex.EncodeToString(b), Side: "right"}},
		MerkleRoot:      hex.EncodeToString(root),
		MerkleAlgorithm: LegacySHA256,
	}
	ok, err := VerifyAuditEvent(p)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v, want true/nil", ok, err)
	}
}

// oldServerProof is exactly what api.trustbeat.eu returns today: no merkle_root,
// no tree_size, no merkle_algorithm.
const oldServerProof = `{
  "event_id": "evt_old",
  "canonical_hash": "abababababababababababababababababababababababababababababababab",
  "batch_id": "batch_old",
  "leaf_index": 0,
  "merkle_path": [{"sibling": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "side": "right"}],
  "anchored_at": "2026-01-01T00:00:00Z"
}`

func parseOldServerProof(t *testing.T) *AuditEventProof {
	t.Helper()
	var w auditEventProofWire
	if err := json.Unmarshal([]byte(oldServerProof), &w); err != nil {
		t.Fatal(err)
	}
	return w.toModel()
}

func TestAnOldServerProofStillParses(t *testing.T) {
	p := parseOldServerProof(t)
	if p.EventID != "evt_old" || len(p.MerklePath) != 1 {
		t.Fatalf("bad parse: %+v", p)
	}
	if p.MerkleRoot != "" || p.TreeSize != 0 {
		t.Fatalf("expected empty root/size, got %q/%d", p.MerkleRoot, p.TreeSize)
	}
	if p.MerkleAlgorithm != LegacySHA256 {
		t.Fatalf("absent algorithm must mean legacy, got %q", p.MerkleAlgorithm)
	}
}

func TestAnOldServerProofIsIncompleteNotInvalid(t *testing.T) {
	// Returning false here would tell a customer their perfectly good audit
	// proof had been tampered with.
	ok, err := VerifyAuditEvent(parseOldServerProof(t))
	if ok {
		t.Fatal("must not report an unverifiable proof as verified")
	}
	var incomplete *IncompleteProofError
	if !errors.As(err, &incomplete) {
		t.Fatalf("want *IncompleteProofError, got %T: %v", err, err)
	}
	var verification *VerificationError
	if errors.As(err, &verification) {
		t.Fatal("IncompleteProofError must not be a VerificationError")
	}
}

func TestVerifyAuditEventRejectsAnUnknownAlgorithm(t *testing.T) {
	p := rfc6962AuditProof()
	p.MerkleAlgorithm = "sha3-future"
	_, err := VerifyAuditEvent(p)
	var unsupported *UnsupportedAlgorithmError
	if !errors.As(err, &unsupported) {
		t.Fatalf("want *UnsupportedAlgorithmError, got %T: %v", err, err)
	}
}
