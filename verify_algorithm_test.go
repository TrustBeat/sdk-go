package trustbeat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// proofWith builds a minimal AnchorProof for verification tests.
func proofWith(hash, root string, path []ProofStep, algorithm string) *AnchorProof {
	return &AnchorProof{
		ID: "p1", Hash: hash, HashAlgorithm: "SHA-256", BatchID: "b1",
		LeafIndex: 0, MerkleRoot: root, ProofPath: path,
		TokenFormat: "RFC3161_DER", TSASerial: "1", Provider: "test",
		AnchoredAt: "2026-01-01T00:00:00Z", MerkleAlgorithm: algorithm,
	}
}

func TestEmptyAlgorithmIsLegacy(t *testing.T) {
	// Proofs issued before the field existed must keep verifying forever.
	leaf := sha256.Sum256([]byte("a"))
	h := hex.EncodeToString(leaf[:])
	ok, err := Verify(proofWith(h, h, nil, ""))
	if err != nil || !ok {
		t.Fatalf("want valid, got ok=%v err=%v", ok, err)
	}
}

func TestRFC6962HashesTheLeaf(t *testing.T) {
	leaf := sha256.Sum256([]byte("a"))
	rfcRoot := sha256.Sum256(append([]byte{0x00}, leaf[:]...))

	ok, err := Verify(proofWith(hex.EncodeToString(leaf[:]),
		hex.EncodeToString(rfcRoot[:]), nil, RFC6962SHA256))
	if err != nil || !ok {
		t.Fatalf("rfc6962 root: want valid, got ok=%v err=%v", ok, err)
	}

	// Under rfc6962 a one-leaf root is not the leaf itself.
	ok, err = Verify(proofWith(hex.EncodeToString(leaf[:]),
		hex.EncodeToString(leaf[:]), nil, RFC6962SHA256))
	if err != nil || ok {
		t.Fatalf("legacy root under rfc6962: want invalid, got ok=%v err=%v", ok, err)
	}
}

func TestRFC6962ReferenceVector(t *testing.T) {
	// MTH([SHA256("a"), SHA256("b"), SHA256("c")]) per RFC 6962, leaf 0.
	a := sha256.Sum256([]byte("a"))
	path := []ProofStep{
		{Sibling: "a0d9f0a50b35b9f7d7edc57fb64f4771ddef0fefeaca4e6f949a1514db5b136d", Side: "right"},
		{Sibling: "6a3fc11b79f836bda340e75c8906e961b8adf4d6a08a2b992e3f38cd6ff38ebf", Side: "right"},
	}
	root := "cac3d448d4e20a2ad5eae1f500e63c2a7f9217cd14572ba7fd22e26dc1ec2648"
	ok, err := Verify(proofWith(hex.EncodeToString(a[:]), root, path, RFC6962SHA256))
	if err != nil || !ok {
		t.Fatalf("want valid, got ok=%v err=%v", ok, err)
	}
}

func TestUnknownAlgorithmIsAnErrorNotFalse(t *testing.T) {
	// "I cannot check this" must not look like "this proof is forged".
	leaf := sha256.Sum256([]byte("a"))
	h := hex.EncodeToString(leaf[:])
	_, err := Verify(proofWith(h, h, nil, "sha3-512-tree"))
	var target *UnsupportedAlgorithmError
	if !errors.As(err, &target) {
		t.Fatalf("want UnsupportedAlgorithmError, got %#v", err)
	}
}

// Vectors below are taken verbatim from Google's transparency-dev/merkle
// (rfc6962_test.go) — a third-party implementation. Our own arithmetic only
// proves self-consistency; these prove conformance.
const (
	upstreamEntry     = "4c313233343536" // hex of "L123456"
	upstreamLeaf      = "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56"
	upstreamEmptyLeaf = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
	upstreamRoot2     = "bf9ae70442844df993ca0001a7c8a095c5f145857960b1ee389df6cbe84b5bf3"
)

func TestLeafHashMatchesUpstreamVector(t *testing.T) {
	// SHA-256(0x00 || "L123456") per transparency-dev/merkle.
	ok, err := Verify(proofWith(upstreamEntry, upstreamLeaf, nil, RFC6962SHA256))
	if err != nil || !ok {
		t.Fatalf("want valid, got ok=%v err=%v", ok, err)
	}
}

func TestRFC6962LeftSiblingAppliesNodePrefix(t *testing.T) {
	// Two-leaf tree whose BOTH leaf hashes are upstream vectors.
	// Exercises Side "left", which no other rfc6962 test reaches.
	path := []ProofStep{{Sibling: upstreamEmptyLeaf, Side: "left"}}
	ok, err := Verify(proofWith(upstreamEntry, upstreamRoot2, path, RFC6962SHA256))
	if err != nil || !ok {
		t.Fatalf("want valid, got ok=%v err=%v", ok, err)
	}
}

// ── Shared RFC 6962 fixture ──────────────────────────────────────────────────
//
// tests/fixtures/rfc6962-proofs.json is checked by the Scala engine and by every
// other SDK, so this pins cross-implementation agreement rather than
// self-consistency.

type fixtureDoc struct {
	MerkleRoot string `json:"merkle_root"`
	Proofs     []struct {
		Hash            string `json:"hash"`
		LeafIndex       int    `json:"leaf_index"`
		MerkleRoot      string `json:"merkle_root"`
		MerkleAlgorithm string `json:"merkle_algorithm"`
		ProofPath       []struct {
			Sibling string `json:"sibling"`
			Side    string `json:"side"`
		} `json:"proof_path"`
	} `json:"proofs"`
}

func loadFixture(t *testing.T) fixtureDoc {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 8; i++ {
		f := filepath.Join(dir, "tests", "fixtures", "rfc6962-proofs.json")
		if raw, err := os.ReadFile(f); err == nil {
			var doc fixtureDoc
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("fixture parse: %v", err)
			}
			return doc
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("rfc6962-proofs.json not found")
	return fixtureDoc{}
}

func fixtureProof(p struct {
	Hash            string `json:"hash"`
	LeafIndex       int    `json:"leaf_index"`
	MerkleRoot      string `json:"merkle_root"`
	MerkleAlgorithm string `json:"merkle_algorithm"`
	ProofPath       []struct {
		Sibling string `json:"sibling"`
		Side    string `json:"side"`
	} `json:"proof_path"`
}, hash string) *AnchorProof {
	steps := make([]ProofStep, len(p.ProofPath))
	for i, s := range p.ProofPath {
		steps[i] = ProofStep{Sibling: s.Sibling, Side: s.Side}
	}
	return proofWith(hash, p.MerkleRoot, steps, p.MerkleAlgorithm)
}

func TestSharedFixtureProofsVerify(t *testing.T) {
	doc := loadFixture(t)
	for _, p := range doc.Proofs {
		ok, err := Verify(fixtureProof(p, p.Hash))
		if err != nil || !ok {
			t.Fatalf("leaf %d: ok=%v err=%v", p.LeafIndex, ok, err)
		}
	}
}

func TestSharedFixtureTamperedProofFails(t *testing.T) {
	// Guards against the suite passing because verification is a no-op.
	doc := loadFixture(t)
	p := doc.Proofs[0]
	ok, err := Verify(fixtureProof(p, strings.Repeat("00", 32)))
	if err != nil || ok {
		t.Fatalf("want invalid, got ok=%v err=%v", ok, err)
	}
}
