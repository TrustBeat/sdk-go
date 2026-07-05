# TrustBeat Go SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

Part of **[TrustBeat](https://trustbeat.eu)** — digital trust infrastructure for the EU.

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

## Requirements

- Go 1.21+
- Zero runtime dependencies (net/http, encoding/json, crypto/sha256 from stdlib)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)
