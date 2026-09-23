package trustbeat

import (
	"context"
	"time"
)

// SetSleep replaces how c waits between 429 retries. Test-only: this file is
// compiled into the package only by `go test`, so it is not public API.
func SetSleep(c *Client, f func(ctx context.Context, d time.Duration) error) { c.sleep = f }
