# TrustBeat Go SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

Part of **[TrustBeat](https://trustbeat.eu)** — digital trust infrastructure for the EU.
All SDKs (Python, TypeScript, Java, C#, Go): **[trustbeat.eu/sdks](https://trustbeat.eu/sdks)**.

## Install

```bash
go get github.com/TrustBeat/sdk-go
```

## Quickstart

```go
package main

import (
    "context"
    "fmt"
    "log"

    trustbeat "github.com/TrustBeat/sdk-go"
)

func main() {
    client, err := trustbeat.NewClient("tb_live_...")
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Anchor a file (SHA-256 computed locally, file never leaves your machine).
    // AnchorFileWait blocks until the proof is ready (next batch, up to 11 min).
    proof, err := client.AnchorFileWait(ctx, "contract.pdf", nil, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(proof.ID)          // tracking ID
    fmt.Println(proof.AnchoredAt)  // RFC 3339 timestamp
    fmt.Println(proof.MerkleRoot)  // Merkle root of the batch

    // Verify locally — no network call
    valid, err := client.Verify(proof)

    // Or anchor a raw SHA-256 hash without blocking, then wait for the proof.
    job, err := client.Anchor(ctx, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", nil)
    proof, err = client.AnchorWait(ctx, job.ID, nil)  // polls up to 11 min

    _ = valid
}
```

## Tamper-Evident Logs (NIS2)

Anchor a log hash together with canonical metadata for NIS2 Article 21 audit trails.
The server seals the metadata into the Merkle leaf, so the proof covers both the log
content and its context.

```go
c, _ := trustbeat.NewClient("tb_live_...")
ctx := context.Background()

// Hash the log yourself — content never leaves your machine.
logHash, _ := trustbeat.HashFile("app.log")

meta := &trustbeat.LogMetadata{
    LogSource:      trustbeat.LogSource{URI: "/var/log/app.log", Name: "Application log"},
    SourceIdentity: trustbeat.LogSourceIdentity{Hostname: "web-01", ServiceName: "payments"},
    TimeEnvelope:   &trustbeat.LogTimeEnvelope{StartAt: "2026-04-15T00:00:00Z", EndAt: "2026-04-15T23:59:59Z"},
}
job, _ := c.AnchorLog(ctx, logHash, meta, "incident-2026-05")
fmt.Println(job.ID, job.CombinedHash)

// Wait for the qualified anchor (next batch, up to ~11 min).
proof, _ := c.AnchorLogWait(ctx, job.ID, nil)
fmt.Println(proof.VerificationStatus) // "VERIFIED"
```

## Webhooks

If your account has a webhook secret configured, every delivery is signed with
an `X-TrustBeat-Signature` header. Verify it with the raw request body —
before any JSON parsing:

```go
ok, err := trustbeat.VerifyWebhookSignature(rawBody, r.Header.Get("X-TrustBeat-Signature"), webhookSecret, nil)
if err != nil || !ok {
    http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
    return
}
```

Rejects replays older than 5 minutes by default (`WebhookVerifyOptions.Tolerance`
to override).

Portable proof bundles for offline verification: `ExportAiDecision(ctx, id)`,
`ExportVerification(ctx, id)`, `ExportLog(ctx, id)` — each returns raw JSON bundle bytes.

## Requirements

- Go 1.21+
- Zero runtime dependencies (net/http, encoding/json, crypto/sha256 from stdlib)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)
