package trustbeat

// Unit tests for webhook signature verification — fully offline.
//
// Signatures are constructed exactly the way the server builds them
// (WebhookDispatcher.scala): hex(HMAC-SHA256(utf8(secret), "<ts>.<body>")).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	whSecret = "abababababababababababababababababababababababababababababababab"
	whNow    = int64(1752000000)
)

var whBody = []byte(`{"event":"anchor.completed","id":"track-1","hash":"aa"}`)

func whSign(body []byte, secret string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func TestWebhookValidSignature(t *testing.T) {
	ok, err := VerifyWebhookSignature(whBody, whSign(whBody, whSecret, whNow), whSecret, &WebhookVerifyOptions{Now: whNow})
	if err != nil || !ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookKeyIsUTF8NotDecodedHex(t *testing.T) {
	// Signing with the hex-decoded secret must NOT verify: the server keys
	// the HMAC with the UTF-8 bytes of the secret string as-is.
	raw, _ := hex.DecodeString(whSecret)
	mac := hmac.New(sha256.New, raw)
	fmt.Fprintf(mac, "%d.", whNow)
	mac.Write(whBody)
	header := fmt.Sprintf("t=%d,v1=%s", whNow, hex.EncodeToString(mac.Sum(nil)))
	ok, err := VerifyWebhookSignature(whBody, header, whSecret, &WebhookVerifyOptions{Now: whNow})
	if err != nil || ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookTamperedPayloadRejected(t *testing.T) {
	header := whSign(whBody, whSecret, whNow)
	tampered := []byte(strings.Replace(string(whBody), "track-1", "track-2", 1))
	ok, err := VerifyWebhookSignature(tampered, header, whSecret, &WebhookVerifyOptions{Now: whNow})
	if err != nil || ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookWrongSecretRejected(t *testing.T) {
	header := whSign(whBody, whSecret, whNow)
	wrong := strings.Repeat("cd", 32)
	ok, err := VerifyWebhookSignature(whBody, header, wrong, &WebhookVerifyOptions{Now: whNow})
	if err != nil || ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookUppercaseHexAccepted(t *testing.T) {
	header := whSign(whBody, whSecret, whNow)
	upper := strings.Replace(header, "v1=", "v1=", 1)
	upper = "t=" + strings.TrimPrefix(strings.Split(upper, ",")[0], "t=") + ",v1=" +
		strings.ToUpper(strings.TrimPrefix(strings.Split(upper, ",")[1], "v1="))
	ok, err := VerifyWebhookSignature(whBody, upper, whSecret, &WebhookVerifyOptions{Now: whNow})
	if err != nil || !ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookStaleTimestampRejected(t *testing.T) {
	header := whSign(whBody, whSecret, whNow-301)
	ok, err := VerifyWebhookSignature(whBody, header, whSecret, &WebhookVerifyOptions{Now: whNow})
	if err != nil || ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookFutureTimestampRejected(t *testing.T) {
	header := whSign(whBody, whSecret, whNow+301)
	ok, err := VerifyWebhookSignature(whBody, header, whSecret, &WebhookVerifyOptions{Now: whNow})
	if err != nil || ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookToleranceBoundaryAccepted(t *testing.T) {
	header := whSign(whBody, whSecret, whNow-300)
	ok, err := VerifyWebhookSignature(whBody, header, whSecret, &WebhookVerifyOptions{Now: whNow})
	if err != nil || !ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookCustomTolerance(t *testing.T) {
	header := whSign(whBody, whSecret, whNow-500)
	ok, _ := VerifyWebhookSignature(whBody, header, whSecret, &WebhookVerifyOptions{Now: whNow})
	if ok {
		t.Error("expected rejection at default tolerance")
	}
	ok, err := VerifyWebhookSignature(whBody, header, whSecret, &WebhookVerifyOptions{Now: whNow, Tolerance: 10 * time.Minute})
	if err != nil || !ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookMalformedHeaderErrors(t *testing.T) {
	for _, bad := range []string{"", "v1=abc", "t=123", "t=abc,v1=def", "nonsense"} {
		ok, err := VerifyWebhookSignature(whBody, bad, whSecret, &WebhookVerifyOptions{Now: whNow})
		if ok || err == nil {
			t.Errorf("header %q: ok=%v err=%v", bad, ok, err)
			continue
		}
		var verr *VerificationError
		if !errors.As(err, &verr) {
			t.Errorf("header %q: expected *VerificationError, got %T", bad, err)
		}
	}
}

func TestWebhookEmptySecretErrors(t *testing.T) {
	header := whSign(whBody, whSecret, whNow)
	ok, err := VerifyWebhookSignature(whBody, header, "", &WebhookVerifyOptions{Now: whNow})
	if ok || err == nil {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookExtraHeaderPartsTolerated(t *testing.T) {
	// Future-proofing: unknown scheme versions (e.g. v2=…) must not break v1.
	header := whSign(whBody, whSecret, whNow) + ",v2=futurestuff"
	ok, err := VerifyWebhookSignature(whBody, header, whSecret, &WebhookVerifyOptions{Now: whNow})
	if err != nil || !ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestWebhookNilOptionsUsesWallClock(t *testing.T) {
	header := whSign(whBody, whSecret, time.Now().Unix())
	ok, err := VerifyWebhookSignature(whBody, header, whSecret, nil)
	if err != nil || !ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}
