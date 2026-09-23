package trustbeat_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	trustbeat "github.com/TrustBeat/sdk-go"
)

// scripted answers the n-th request with steps[n] (the last step repeats) and counts requests.
type step struct {
	status     int
	retryAfter string
	body       string
}

func scripted(t *testing.T, steps ...step) (*httptest.Server, *int32) {
	t.Helper()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(atomic.AddInt32(&n, 1)) - 1
		if i >= len(steps) {
			i = len(steps) - 1
		}
		if steps[i].retryAfter != "" {
			w.Header().Set("Retry-After", steps[i].retryAfter)
		}
		writeJSON(w, steps[i].status, steps[i].body)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func limited(retryAfter string) step {
	return step{429, retryAfter, `{"error":{"code":"RATE_LIMITED","message":"Slow down"}}`}
}

var accepted = step{202, "", `{"id":"track-1","hash":"` + strings.Repeat("a", 64) + `","hash_algorithm":"SHA-256","status":"pending","submitted_at":"2026-09-23T10:00:00Z"}`}

// recordingClient records the waits instead of sleeping them.
func recordingClient(t *testing.T, srv *httptest.Server, opts ...trustbeat.Option) (*trustbeat.Client, *[]time.Duration) {
	t.Helper()
	c, err := trustbeat.NewClient("tb_live_test", append([]trustbeat.Option{trustbeat.WithBaseURL(srv.URL + "/v1")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	trustbeat.SetSleep(c, func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil })
	return c, &waits
}

func TestRetryWaitsRetryAfterThenSucceeds(t *testing.T) {
	srv, n := scripted(t, limited("3"), accepted)
	c, waits := recordingClient(t, srv)
	job, err := c.Anchor(context.Background(), strings.Repeat("a", 64), nil)
	if err != nil {
		t.Fatal(err)
	}
	if job.ID != "track-1" || *n != 2 || !reflect.DeepEqual(*waits, []time.Duration{3 * time.Second}) {
		t.Errorf("id=%s requests=%d waits=%v", job.ID, *n, *waits)
	}
}

func TestRetryGivesUpAfterMaxRetriesWithRetryAfter(t *testing.T) {
	srv, n := scripted(t, limited("2"))
	c, waits := recordingClient(t, srv, trustbeat.WithMaxRetries(2))
	_, err := c.Anchor(context.Background(), strings.Repeat("a", 64), nil)
	var rle *trustbeat.RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	if rle.RetryAfter != 2*time.Second || rle.Status != 429 || rle.ErrorCode != "RATE_LIMITED" {
		t.Errorf("error = %+v", rle)
	}
	if *n != 3 || len(*waits) != 2 {
		t.Errorf("requests=%d waits=%v, want 3 requests and 2 waits", *n, *waits)
	}
}

func TestRetryDisabledWithZero(t *testing.T) {
	srv, n := scripted(t, limited("1"))
	c, waits := recordingClient(t, srv, trustbeat.WithMaxRetries(0))
	_, err := c.Anchor(context.Background(), strings.Repeat("a", 64), nil)
	var rle *trustbeat.RateLimitError
	if !errors.As(err, &rle) || *n != 1 || len(*waits) != 0 {
		t.Errorf("err=%v requests=%d waits=%v", err, *n, *waits)
	}
}

func TestRetryBacksOffWithoutRetryAfter(t *testing.T) {
	srv, _ := scripted(t, limited(""), limited(""), accepted)
	c, waits := recordingClient(t, srv)
	if _, err := c.Anchor(context.Background(), strings.Repeat("a", 64), nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*waits, []time.Duration{time.Second, 2 * time.Second}) {
		t.Errorf("waits = %v, want [1s 2s]", *waits)
	}
}

func TestRetryReturnsAWaitOver60sInsteadOfWaiting(t *testing.T) {
	srv, _ := scripted(t, limited("120"))
	c, waits := recordingClient(t, srv)
	_, err := c.Anchor(context.Background(), strings.Repeat("a", 64), nil)
	var rle *trustbeat.RateLimitError
	if !errors.As(err, &rle) || rle.RetryAfter != 120*time.Second || len(*waits) != 0 {
		t.Errorf("err=%v waits=%v", err, *waits)
	}
}

func TestRetryDoesNotRetryOtherErrors(t *testing.T) {
	// A 5xx may come after the hash was queued; retrying it could anchor it twice.
	srv, n := scripted(t, step{503, "", `{"error":{"message":"busy"}}`})
	c, waits := recordingClient(t, srv)
	if _, err := c.Anchor(context.Background(), strings.Repeat("a", 64), nil); err == nil {
		t.Fatal("expected an error")
	}
	if *n != 1 || len(*waits) != 0 {
		t.Errorf("requests=%d waits=%v", *n, *waits)
	}
}

func TestRetryAppliesToBatchSubmissions(t *testing.T) {
	srv, n := scripted(t, limited("1"), step{202, "", `{"submission_id":"sub_1","accepted":[],"total":0}`})
	c, _ := recordingClient(t, srv)
	if _, err := c.AnchorBatch(context.Background(), []string{strings.Repeat("a", 64)}, nil); err != nil {
		t.Fatal(err)
	}
	if *n != 2 {
		t.Errorf("requests = %d, want 2", *n)
	}
}

func TestRetryWaitStopsOnContextCancel(t *testing.T) {
	// The real sleep, not the recorder: a cancelled context must end the wait at once.
	srv, _ := scripted(t, limited("30"))
	c, _ := trustbeat.NewClient("tb_live_test", trustbeat.WithBaseURL(srv.URL+"/v1"))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Anchor(ctx, strings.Repeat("a", 64), nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Errorf("err=%v after %v", err, time.Since(start))
	}
}

func TestNegativeMaxRetriesIsRejected(t *testing.T) {
	if _, err := trustbeat.NewClient("tb_live_test", trustbeat.WithMaxRetries(-1)); err == nil {
		t.Fatal("expected an error")
	}
}
