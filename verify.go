package trustbeat

// Verify recomputes the Merkle root from the proof path and compares it to
// AnchorProof.MerkleRoot using a constant-time comparison.
//
// Returns true if the proof is cryptographically valid.
// Returns a *VerificationError if the proof data is malformed (bad hex, unknown side).
// Returns false (with nil error) if the computed root does not match the stored root.
//
// The fold depends on the construction the proof declares in MerkleAlgorithm:
//
//	trustbeat-legacy-sha256  leaf = your hash, parent = SHA-256(left || right)
//	rfc6962-sha256           leaf = SHA-256(0x00 || your hash),
//	                         parent = SHA-256(0x01 || left || right)
//
// In both, the Side field gives the sibling's position:
//
//	"left"  → sibling is left  → hash over (sibling, current)
//	"right" → sibling is right → hash over (current, sibling)
//
// A proof with an empty MerkleAlgorithm predates the field and is legacy.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Verify verifies a Merkle inclusion proof locally — no network call.
func Verify(proof *AnchorProof) (bool, error) {
	algorithm := proof.MerkleAlgorithm
	if algorithm == "" {
		algorithm = LegacySHA256
	}
	var leafPrefix, nodePrefix []byte
	switch algorithm {
	case LegacySHA256:
		// no domain separation
	case RFC6962SHA256:
		leafPrefix, nodePrefix = []byte{0x00}, []byte{0x01}
	default:
		return false, &UnsupportedAlgorithmError{TrustBeatError{
			Message: fmt.Sprintf(
				"unsupported merkle_algorithm %q: this SDK understands %q and %q; "+
					"upgrade the SDK, or verify via the API",
				algorithm, LegacySHA256, RFC6962SHA256),
		}}
	}

	current, err := hex.DecodeString(proof.Hash)
	if err != nil {
		return false, &VerificationError{TrustBeatError{
			Message: fmt.Sprintf("invalid leaf hash hex: %q", proof.Hash),
		}}
	}
	if len(leafPrefix) > 0 {
		h := sha256.New()
		h.Write(leafPrefix)
		h.Write(current)
		current = h.Sum(nil)
	}

	for i, step := range proof.ProofPath {
		sibling, err := hex.DecodeString(step.Sibling)
		if err != nil {
			return false, &VerificationError{TrustBeatError{
				Message: fmt.Sprintf("invalid sibling hex at step %d: %q", i, step.Sibling),
			}}
		}
		h := sha256.New()
		h.Write(nodePrefix)
		switch step.Side {
		case "left":
			// sibling is the left child
			h.Write(sibling)
			h.Write(current)
		case "right":
			// sibling is the right child
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

// VerifyAuditEvent verifies an audit event's Merkle inclusion proof locally —
// no network call. The audit counterpart of Verify, for the shape that names the
// leaf CanonicalHash and the path MerklePath.
//
// Returns true if the proof is cryptographically valid, false (with nil error)
// if the computed root does not match.
//
// Returns an *IncompleteProofError when the proof carries no MerkleRoot: servers
// before API 1.46 did not send one, so there is nothing to fold against. That is
// "cannot check", never "invalid". Returns *UnsupportedAlgorithmError and
// *VerificationError on the same terms as Verify.
func VerifyAuditEvent(proof *AuditEventProof) (bool, error) {
	if proof.MerkleRoot == "" {
		return false, &IncompleteProofError{TrustBeatError{
			Message: "this audit event proof has no merkle_root, so it cannot be folded " +
				"locally; the server that issued it predates API 1.46 — verify it " +
				"server-side via the API, or re-fetch it from an upgraded server",
		}}
	}
	// Reuse the anchor fold: the two shapes differ only in field names.
	path := make([]ProofStep, len(proof.MerklePath))
	for i, s := range proof.MerklePath {
		path[i] = ProofStep{Sibling: s.Sibling, Side: s.Side}
	}
	return Verify(&AnchorProof{
		Hash:            proof.CanonicalHash,
		MerkleRoot:      proof.MerkleRoot,
		ProofPath:       path,
		MerkleAlgorithm: proof.MerkleAlgorithm,
	})
}
