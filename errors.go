package trustbeat

import (
	"fmt"
	"time"
)

// TrustBeatError is the base error type for all SDK errors.
type TrustBeatError struct {
	Message   string
	Status    int
	RequestID string
	ErrorCode string // API error code from the response body, e.g. "NOT_FOUND", "NOT_ANCHORED"
}

func (e TrustBeatError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status)
	}
	return e.Message
}

// AuthError is returned for HTTP 401 (invalid or missing API key).
type AuthError struct{ TrustBeatError }

// NotFoundError is returned for HTTP 404.
type NotFoundError struct{ TrustBeatError }

// QuotaError is returned for HTTP 402 or QUOTA_EXCEEDED.
type QuotaError struct{ TrustBeatError }

// RateLimitError is returned for HTTP 429, once the client's automatic retries
// (see WithMaxRetries) are spent. A refused submission was not queued, so retrying
// it can never anchor a hash twice.
type RateLimitError struct {
	TrustBeatError
	// RetryAfter is how long the server asked to wait before the next attempt
	// (the Retry-After header); zero when it sent none.
	RetryAfter time.Duration
}

// VerificationError is returned when local Merkle proof verification fails.
type VerificationError struct{ TrustBeatError }

// IncompleteProofError is returned when a proof does not carry the fields needed
// to check it locally.
//
// Audit event proofs from servers older than API 1.46 have no MerkleRoot, so
// there is nothing to fold the path against. Like UnsupportedAlgorithmError it is
// deliberately not a VerificationError and never a false return: "I cannot check
// this proof" must not be mistaken for "this proof is forged". Verify server-side
// via the API, or upgrade the server.
type IncompleteProofError struct{ TrustBeatError }

// UnsupportedAlgorithmError is returned when a proof declares a MerkleAlgorithm
// this SDK version does not implement.
//
// It is deliberately not a VerificationError and never a false return: "I cannot
// check this proof" must not be mistaken for "this proof is forged". Upgrade the
// SDK, or verify server-side via the API.
type UnsupportedAlgorithmError struct{ TrustBeatError }
