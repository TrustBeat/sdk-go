package trustbeat

// Verify recomputes the Merkle root from the proof path and compares it to
// AnchorProof.MerkleRoot using a constant-time comparison.
//
// Returns true if the proof is cryptographically valid.
// Returns a *VerificationError if the proof data is malformed (bad hex, unknown side).
// Returns false (with nil error) if the computed root does not match the stored root.
//
// Algorithm (mirrors MerkleEngine.scala and all other SDK implementations):
//
//	parent = SHA-256(left_child_bytes || right_child_bytes)
//
// The Side field in each ProofStep gives the sibling's position:
//
//	"left"  → sibling is left  → SHA-256(sibling || current)
//	"right" → sibling is right → SHA-256(current || sibling)

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Verify verifies a Merkle inclusion proof locally — no network call.
func Verify(proof *AnchorProof) (bool, error) {
	current, err := hex.DecodeString(proof.Hash)
	if err != nil {
		return false, &VerificationError{TrustBeatError{
			Message: fmt.Sprintf("invalid leaf hash hex: %q", proof.Hash),
		}}
	}

	for i, step := range proof.ProofPath {
		sibling, err := hex.DecodeString(step.Sibling)
		if err != nil {
			return false, &VerificationError{TrustBeatError{
				Message: fmt.Sprintf("invalid sibling hex at step %d: %q", i, step.Sibling),
			}}
		}
		h := sha256.New()
		switch step.Side {
		case "left":
			// sibling is the left child → SHA-256(sibling || current)
			h.Write(sibling)
			h.Write(current)
		case "right":
			// sibling is the right child → SHA-256(current || sibling)
			h.Write(current)
			h.Write(sibling)
		default:
			return false, &VerificationError{TrustBeatError{
				Message: fmt.Sprintf("unknown side %q at step %d: want \"left\" or \"right\"", step.Side, i),
			}}
		}
		current = h.Sum(nil)
	}

	expected, err := hex.DecodeString(proof.MerkleRoot)
	if err != nil {
		return false, &VerificationError{TrustBeatError{
			Message: fmt.Sprintf("invalid merkle_root hex: %q", proof.MerkleRoot),
		}}
	}

	return subtle.ConstantTimeCompare(current, expected) == 1, nil
}
