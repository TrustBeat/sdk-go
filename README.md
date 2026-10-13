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

## Signature Preservation (not yet available)

> **Not yet available** — the API answers `404` until the product is launched.

Preserves the electronic signatures of a signed file (PAdES, XAdES, CAdES, ASiC-E, ASiC-S) for 30
years. **The signed file never reaches TrustBeat, and this SDK does not read it:** the
`trustbeat-signature` extractor reads it on your machine and writes a submission JSON (the signatures and the digests that
bind them to the file), which the SDK sends unchanged.

```bash
trustbeat-signature extract contract.pdf --out contract.submission.json
```

```go
submission, _ := os.ReadFile("contract.submission.json")

rec, err := c.PreserveSignatures(ctx, submission, &trustbeat.PreserveOptions{ClientRef: "contract-17"}) // one anchor against the quota
rec, err = c.GetSignaturePreservation(ctx, rec.ID) // Status: pending -> anchored -> preserved
recs, err := c.ListSignaturePreservations(ctx, 50)

pkg, err := c.DownloadSignaturePreservationPackage(ctx, rec.ID) // ZIP for offline verification
os.WriteFile("package.zip", pkg, 0o644)

// Years later: the file presented now, extracted again
now, _ := os.ReadFile("now.submission.json")
report, err := c.VerifySignaturePreservation(ctx, rec.ID, now)
fmt.Println(report.Result, report.Steps[0].Name, report.Steps[0].Result)
pdf, err := c.VerifySignaturePreservationPDF(ctx, rec.ID, now)
```

Verifying later works with the original file only: `trustbeat-signature extract` it again and pass that
submission. A file that does not match is a report with failed steps, not an error. Offline, without
TrustBeat: `trustbeat-signature verify contract.pdf --package package.zip`.

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

## Batches and rate limits

A batch carries up to **1,000** hashes and is all-or-nothing: if the call fails, none of them
was queued. (API servers deployed before 26 Sep 2026 accept at most 100.)

Anchoring is rate-limited per account (see your plan). A rate-limited request (HTTP 429) is
**retried automatically**, waiting the `Retry-After` the server sends — twice by default.
Retrying is always safe: a refused submission was never queued. When the retries run out you
get the rate-limit error, carrying the wait the server asked for.

```go
client, err := trustbeat.NewClient("tb_live_...", trustbeat.WithMaxRetries(2)) // 0 turns retrying off
if err != nil {
    log.Fatal(err)
}

submission, err := client.AnchorBatch(ctx, hashes, nil) // up to trustbeat.MaxBatchSize (1,000)
var rle *trustbeat.RateLimitError
if errors.As(err, &rle) {
    log.Printf("still limited; server asked to wait %s", rle.RetryAfter)
}
```

The wait between retries honours `ctx`: cancelling it ends the wait at once.

## Requirements

- Go 1.21+
- Zero runtime dependencies (net/http, encoding/json, crypto/sha256 from stdlib)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)


### Merkle algorithm

Every proof declares how it must be folded, in `proof.MerkleAlgorithm`:

| Value | Construction |
|---|---|
| `trustbeat-legacy-sha256` | leaf = your hash, parent = `SHA-256(left \|\| right)` |
| `rfc6962-sha256` | leaf = `SHA-256(0x00 \|\| hash)`, parent = `SHA-256(0x01 \|\| left \|\| right)` |

`Verify` dispatches on it for you. A proof with an empty label was issued before
the field existed and is legacy. An algorithm this SDK version does not implement
returns an `*UnsupportedAlgorithmError` rather than `false` — "cannot check" is
not "invalid".

### Audit event proofs

`VerifyAuditEvent` folds an audit event proof the same way:

```go
proof, err := c.GetAuditEventProof(ctx, eventID)
if err != nil { log.Fatal(err) }

ok, err := trustbeat.VerifyAuditEvent(proof)
var incomplete *trustbeat.IncompleteProofError
if errors.As(err, &incomplete) {
    // The server predates API 1.46 and sent no MerkleRoot, so there is nothing
    // to fold against. The proof is not invalid — verify it server-side instead.
} else if err != nil {
    log.Fatal(err)
} else {
    fmt.Println("valid:", ok)
}
```

Treating that error as a failed proof would be wrong: it means "cannot check",
not "tampered".
