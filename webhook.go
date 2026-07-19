package trustbeat

// Webhook signature verification — no network call.
//
// TrustBeat signs every webhook delivery for accounts with a webhook secret
// configured. Each request carries the header:
//
//	X-TrustBeat-Signature: t=<unix_ts>,v1=<hex(HMAC-SHA256(secret, "<ts>.<body>"))>
//
// The HMAC key is the UTF-8 bytes of the secret string exactly as shown in
// the dashboard (it is *not* hex-decoded first). The signed payload is the
// ASCII timestamp, a literal ".", and the raw request body bytes.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// WebhookVerifyOptions tunes VerifyWebhookSignature. The zero value (or nil)
// uses the defaults: 5-minute tolerance, current wall-clock time.
type WebhookVerifyOptions struct {
	// Tolerance is the maximum allowed |now - t|. Default 5 minutes.
	Tolerance time.Duration
	// Now overrides the current unix time (for testing). Default time.Now().
	Now int64
}

// VerifyWebhookSignature verifies the X-TrustBeat-Signature header of a
// webhook delivery.
//
// Pass the raw request body exactly as received — do not re-serialize the
// JSON, as any formatting difference changes the signature.
//
// Returns (true, nil) if the signature is valid and the timestamp is within
// tolerance; (false, nil) on signature mismatch or a timestamp outside the
// tolerance window (possible replay); and (false, *VerificationError) if the
// header or secret is malformed.
func VerifyWebhookSignature(payload []byte, signatureHeader, secret string, opts *WebhookVerifyOptions) (bool, error) {
	if secret == "" {
		return false, &VerificationError{TrustBeatError{Message: "trustbeat: webhook secret must not be empty"}}
	}
	if signatureHeader == "" {
		return false, &VerificationError{TrustBeatError{Message: "trustbeat: signature header must not be empty"}}
	}

	var tsStr, sigHex string
	for _, part := range strings.Split(signatureHeader, ",") {
		key, value, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "t":
			tsStr = value
		case "v1":
			sigHex = value
		}
	}
	if tsStr == "" || sigHex == "" {
		return false, &VerificationError{TrustBeatError{
			Message: "trustbeat: malformed signature header (expected 't=<ts>,v1=<hex>'): " + signatureHeader,
		}}
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false, &VerificationError{TrustBeatError{Message: "trustbeat: malformed signature timestamp: " + tsStr}}
	}

	tolerance := 5 * time.Minute
	if opts != nil && opts.Tolerance > 0 {
		tolerance = opts.Tolerance
	}
	now := time.Now().Unix()
	if opts != nil && opts.Now != 0 {
		now = opts.Now
	}
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(tolerance/time.Second) {
		return false, nil
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tsStr))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(sigHex))), nil
}
