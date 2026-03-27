// Package trustbeat is the official Go SDK for the TrustBeat Digital Trust API.
//
// Zero runtime dependencies — uses net/http, encoding/json, crypto/sha256 from the stdlib.
// All types and functions are safe for concurrent use.
//
//	client, err := trustbeat.NewClient("tb_live_...")
//	if err != nil { log.Fatal(err) }
//
//	job, err := client.Anchor(ctx, "abc...64hex", nil)
//	proof, err := client.AnchorWait(ctx, job.ID, nil)
//	valid, err := client.Verify(proof)
package trustbeat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.trustbeat.eu/v1"
	sdkVersion     = "0.1.0"
)

// Client is the TrustBeat API client. Create with NewClient.
// Safe for concurrent use; share one instance per application.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// Option is a functional option for NewClient.
type Option func(*Client)

// WithBaseURL overrides the API base URL.
// Default: https://api.trustbeat.eu/v1
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// WithTimeout sets the HTTP request timeout.
// Default: 30 seconds.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// WithHTTPClient replaces the underlying *http.Client.
// Useful for testing or custom transport configuration.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// NewClient creates a TrustBeat API client.
// apiKey must be a non-empty "tb_live_..." or "tb_test_..." key.
func NewClient(apiKey string, opts ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("trustbeat: apiKey must not be empty")
	}
	c := &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// ── Options ──────────────────────────────────────────────────────────────────

// AnchorOptions holds optional metadata for anchor and timestamp requests.
type AnchorOptions struct {
	ClientRef   string // your own reference ID, echoed back in proof responses
	Description string // human-readable label for the anchored content
	CallbackURL string // webhook URL called when anchoring completes (optional)
}

// WaitOptions controls polling behaviour for AnchorWait and AnchorFileWait.
type WaitOptions struct {
	Timeout      time.Duration // maximum time to wait; default 11 minutes
	PollInterval time.Duration // interval between polls; default 15 seconds
}

// ── Public API ────────────────────────────────────────────────────────────────

// Anchor submits a SHA-256 hash for Merkle batch anchoring.
// Returns immediately with a tracking ID (HTTP 202 Accepted).
// Use GetProof or AnchorWait to retrieve the inclusion proof.
func (c *Client) Anchor(ctx context.Context, sha256Hex string, opts *AnchorOptions) (*AnchorJob, error) {
	body := map[string]any{
		"hash":           sha256Hex,
		"hash_algorithm": "sha256",
	}
	applyOpts(body, opts)

	var job anchorJobWire
	if err := c.post(ctx, "/anchors", body, &job); err != nil {
		return nil, err
	}
	return job.toModel(), nil
}

// AnchorBatch submits up to 100 SHA-256 hashes in a single request.
// Returns a slice of AnchorJob objects in the same order as the input.
// Returns nil (no error) for an empty input slice.
func (c *Client) AnchorBatch(ctx context.Context, hashes []string, opts *AnchorOptions) ([]*AnchorJob, error) {
	if len(hashes) == 0 {
		return nil, nil
	}
	if len(hashes) > 100 {
		return nil, fmt.Errorf("trustbeat: AnchorBatch accepts at most 100 hashes per call")
	}
	items := make([]map[string]any, len(hashes))
	for i, h := range hashes {
		items[i] = map[string]any{"hash": h, "hash_algorithm": "sha256"}
	}
	body := map[string]any{"hashes": items}
	if opts != nil {
		if opts.ClientRef != "" {
			body["client_ref"] = opts.ClientRef
		}
		if opts.Description != "" {
			body["description"] = opts.Description
		}
	}
	var resp struct {
		Accepted []anchorJobWire `json:"accepted"`
	}
	if err := c.post(ctx, "/anchors/batch", body, &resp); err != nil {
		return nil, err
	}
	jobs := make([]*AnchorJob, len(resp.Accepted))
	for i := range resp.Accepted {
		jobs[i] = resp.Accepted[i].toModel()
	}
	return jobs, nil
}

// GetProof retrieves the inclusion proof for a previously submitted hash.
// Returns (nil, nil) if the hash is still pending (not yet included in a batch).
// Returns (*NotFoundError, ...) if the tracking ID is unknown.
func (c *Client) GetProof(ctx context.Context, trackingID string) (*AnchorProof, error) {
	path := "/anchors/" + url.PathEscape(trackingID)
	var p proofWire
	if err := c.get(ctx, path, &p); err != nil {
		return nil, err
	}
	if p.MerkleRoot == "" {
		return nil, nil // still pending
	}
	return p.toModel(), nil
}

// AnchorWait polls GetProof until the inclusion proof is ready, then returns it.
// opts may be nil (defaults: 11-minute timeout, 15-second poll interval).
// Respects ctx cancellation.
func (c *Client) AnchorWait(ctx context.Context, trackingID string, opts *WaitOptions) (*AnchorProof, error) {
	timeout, poll := 11*time.Minute, 15*time.Second
	if opts != nil {
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
		if opts.PollInterval > 0 {
			poll = opts.PollInterval
		}
	}
	deadline := time.Now().Add(timeout)
	for {
		proof, err := c.GetProof(ctx, trackingID)
		if err != nil {
			return nil, err
		}
		if proof != nil {
			return proof, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("trustbeat: AnchorWait timed out after %v for %s", timeout, trackingID)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// Verify verifies a Merkle inclusion proof locally — no network call.
// Delegates to the package-level Verify function.
func (c *Client) Verify(proof *AnchorProof) (bool, error) {
	return Verify(proof)
}

// Timestamp issues a dedicated (non-batched) RFC 3161 qualified timestamp for a single hash.
// Consumes 1 credit. Returns synchronously, usually sub-second.
func (c *Client) Timestamp(ctx context.Context, sha256Hex string, opts *AnchorOptions) (*TimestampResult, error) {
	body := map[string]any{
		"hash":           sha256Hex,
		"hash_algorithm": "sha256",
	}
	applyOpts(body, opts)
	var ts timestampWire
	if err := c.post(ctx, "/timestamps", body, &ts); err != nil {
		return nil, err
	}
	return ts.toModel(), nil
}

// ── File helpers ──────────────────────────────────────────────────────────────

// HashFile computes the SHA-256 hash of a local file, returned as a lowercase
// hex string. The file is read in 64 KB chunks and is never uploaded.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("trustbeat: HashFile: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	buf := make([]byte, 65536)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", fmt.Errorf("trustbeat: HashFile: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashBytes computes the SHA-256 hash of a byte slice, returned as a lowercase hex string.
func HashBytes(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// HashString computes the SHA-256 hash of a UTF-8 string, returned as a lowercase hex string.
func HashString(s string) string {
	return HashBytes([]byte(s))
}

// AnchorFile hashes a local file with SHA-256 and submits it for anchoring.
// The file is never uploaded — only the 64-character hex digest is sent.
// Description defaults to the filename if not set in opts.
func (c *Client) AnchorFile(ctx context.Context, path string, opts *AnchorOptions) (*AnchorJob, error) {
	hash, err := HashFile(path)
	if err != nil {
		return nil, err
	}
	return c.Anchor(ctx, hash, withFileDesc(opts, path))
}

// AnchorFileWait hashes a local file, submits for anchoring, and waits for the proof.
// Convenience wrapper around AnchorFile + AnchorWait.
func (c *Client) AnchorFileWait(ctx context.Context, path string, opts *AnchorOptions, waitOpts *WaitOptions) (*AnchorProof, error) {
	job, err := c.AnchorFile(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return c.AnchorWait(ctx, job.ID, waitOpts)
}

// ── Low-level HTTP ────────────────────────────────────────────────────────────

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("trustbeat: marshal: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("trustbeat: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "trustbeat-go/"+sdkVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("trustbeat: request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("trustbeat: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapHTTPError(resp.StatusCode, raw)
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("trustbeat: unmarshal response: %w", err)
		}
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func applyOpts(body map[string]any, opts *AnchorOptions) {
	if opts == nil {
		return
	}
	if opts.ClientRef != "" {
		body["client_ref"] = opts.ClientRef
	}
	if opts.Description != "" {
		body["description"] = opts.Description
	}
	if opts.CallbackURL != "" {
		body["callback_url"] = opts.CallbackURL
	}
}

// withFileDesc returns opts with Description set to the filename if not already set.
func withFileDesc(opts *AnchorOptions, path string) *AnchorOptions {
	if opts != nil && opts.Description != "" {
		return opts
	}
	merged := &AnchorOptions{}
	if opts != nil {
		*merged = *opts
	}
	merged.Description = filepath.Base(path)
	return merged
}

func mapHTTPError(status int, body []byte) error {
	msg := fmt.Sprintf("HTTP %d", status)
	var errResp struct {
		Error struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
		msg = errResp.Error.Message
	}
	base := TrustBeatError{Message: msg, Status: status}
	switch status {
	case 401:
		return &AuthError{base}
	case 402:
		return &QuotaError{base}
	case 404:
		return &NotFoundError{base}
	case 429:
		return &RateLimitError{base}
	default:
		return &TrustBeatError{Message: msg, Status: status}
	}
}

// ── Wire types (JSON ↔ model) ─────────────────────────────────────────────────

type anchorJobWire struct {
	ID            string `json:"id"`
	Hash          string `json:"hash"`
	HashAlgorithm string `json:"hash_algorithm"`
	Status        string `json:"status"`
	SubmittedAt   string `json:"submitted_at"`
	Overage       bool   `json:"overage"`
}

func (w anchorJobWire) toModel() *AnchorJob {
	return &AnchorJob{
		ID:            w.ID,
		Hash:          w.Hash,
		HashAlgorithm: w.HashAlgorithm,
		Status:        w.Status,
		SubmittedAt:   w.SubmittedAt,
		Overage:       w.Overage,
	}
}

type proofStepWire struct {
	Sibling string `json:"sibling"`
	Side    string `json:"side"`
}

type proofWire struct {
	ID            string          `json:"id"`
	Hash          string          `json:"hash"`
	HashAlgorithm string          `json:"hash_algorithm"`
	BatchID       string          `json:"batch_id"`
	LeafIndex     int             `json:"leaf_index"`
	MerkleRoot    string          `json:"merkle_root"`
	ProofPath     []proofStepWire `json:"proof_path"`
	Token         string          `json:"token"` // base64-encoded DER
	TokenFormat   string          `json:"token_format"`
	TSASerial     string          `json:"tsa_serial"`
	Provider      string          `json:"provider"`
	AnchoredAt    string          `json:"anchored_at"`
	ClientRef     *string         `json:"client_ref"`
	Description   *string         `json:"description"`
}

func (w *proofWire) toModel() *AnchorProof {
	token, _ := base64.StdEncoding.DecodeString(w.Token)
	steps := make([]ProofStep, len(w.ProofPath))
	for i, s := range w.ProofPath {
		steps[i] = ProofStep{Sibling: s.Sibling, Side: s.Side}
	}
	p := &AnchorProof{
		ID:            w.ID,
		Hash:          w.Hash,
		HashAlgorithm: w.HashAlgorithm,
		BatchID:       w.BatchID,
		LeafIndex:     w.LeafIndex,
		MerkleRoot:    w.MerkleRoot,
		ProofPath:     steps,
		Token:         token,
		TokenFormat:   w.TokenFormat,
		TSASerial:     w.TSASerial,
		Provider:      w.Provider,
		AnchoredAt:    w.AnchoredAt,
	}
	if w.ClientRef != nil {
		p.ClientRef = *w.ClientRef
	}
	if w.Description != nil {
		p.Description = *w.Description
	}
	return p
}

type timestampWire struct {
	ID            string  `json:"id"`
	Hash          string  `json:"hash"`
	HashAlgorithm string  `json:"hash_algorithm"`
	Token         string  `json:"token"` // base64-encoded DER
	TokenFormat   string  `json:"token_format"`
	TSASerial     string  `json:"tsa_serial"`
	Provider      string  `json:"provider"`
	IssuedAt      string  `json:"issued_at"`
	ClientRef     *string `json:"client_ref"`
	Description   *string `json:"description"`
}

func (w *timestampWire) toModel() *TimestampResult {
	token, _ := base64.StdEncoding.DecodeString(w.Token)
	ts := &TimestampResult{
		ID:            w.ID,
		Hash:          w.Hash,
		HashAlgorithm: w.HashAlgorithm,
		Token:         token,
		TokenFormat:   w.TokenFormat,
		TSASerial:     w.TSASerial,
		Provider:      w.Provider,
		IssuedAt:      w.IssuedAt,
	}
	if w.ClientRef != nil {
		ts.ClientRef = *w.ClientRef
	}
	if w.Description != nil {
		ts.Description = *w.Description
	}
	return ts
}
