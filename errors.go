package trustbeat

import "fmt"

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

// RateLimitError is returned for HTTP 429.
type RateLimitError struct{ TrustBeatError }

// VerificationError is returned when local Merkle proof verification fails.
type VerificationError struct{ TrustBeatError }
