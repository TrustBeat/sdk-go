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
	"errors"
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
// Returns a *BatchSubmission grouping all items under a single SubmissionID.
// Returns nil (no error) for an empty input slice.
func (c *Client) AnchorBatch(ctx context.Context, hashes []string, opts *AnchorOptions) (*BatchSubmission, error) {
	if len(hashes) == 0 {
		return &BatchSubmission{}, nil
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
		SubmissionID string          `json:"submission_id"`
		Accepted     []anchorJobWire `json:"accepted"`
	}
	if err := c.post(ctx, "/anchors/batch", body, &resp); err != nil {
		return nil, err
	}
	jobs := make([]*AnchorJob, len(resp.Accepted))
	for i := range resp.Accepted {
		jobs[i] = resp.Accepted[i].toModel()
	}
	return &BatchSubmission{SubmissionID: resp.SubmissionID, Items: jobs}, nil
}

// GetBatchStatus returns anchored/pending counts for a batch submission.
func (c *Client) GetBatchStatus(ctx context.Context, submissionID string) (*BatchStatus, error) {
	var resp struct {
		SubmissionID string `json:"submission_id"`
		Total        int    `json:"total"`
		Anchored     int    `json:"anchored"`
		Pending      int    `json:"pending"`
	}
	if err := c.get(ctx, "/anchors/batch/"+url.PathEscape(submissionID)+"/status", &resp); err != nil {
		return nil, err
	}
	return &BatchStatus{
		SubmissionID: resp.SubmissionID,
		Total:        resp.Total,
		Anchored:     resp.Anchored,
		Pending:      resp.Pending,
	}, nil
}

// GetBatchProofs returns all anchored inclusion proofs for a batch submission.
func (c *Client) GetBatchProofs(ctx context.Context, submissionID string) ([]*AnchorProof, error) {
	var resp struct {
		Proofs []proofWire `json:"proofs"`
	}
	if err := c.get(ctx, "/anchors/batch/"+url.PathEscape(submissionID)+"/proofs", &resp); err != nil {
		return nil, err
	}
	proofs := make([]*AnchorProof, len(resp.Proofs))
	for i := range resp.Proofs {
		proofs[i] = resp.Proofs[i].toModel()
	}
	return proofs, nil
}

// AnchorBatchWait polls GetBatchStatus until all items are anchored, then returns all proofs.
// opts may be nil (defaults: 15-minute timeout, 15-second poll interval).
func (c *Client) AnchorBatchWait(ctx context.Context, submission *BatchSubmission, opts *WaitOptions) ([]*AnchorProof, error) {
	timeout, poll := 15*time.Minute, 15*time.Second
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
		status, err := c.GetBatchStatus(ctx, submission.SubmissionID)
		if err != nil {
			return nil, err
		}
		if status.Pending == 0 && status.Total > 0 {
			return c.GetBatchProofs(ctx, submission.SubmissionID)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("trustbeat: AnchorBatchWait timed out after %v for %s", timeout, submission.SubmissionID)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
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

// ── AI Act Audit Anchoring ────────────────────────────────────────────────────

// AnchorAiDecision submits an AI decision for EU AI Act Article 12 anchoring.
// Privacy-safe: only hashes are sent — raw inputs and outputs are never uploaded.
// Returns immediately with a tracking ID. Use GetAiDecisionProof or
// AnchorAiDecisionWait to retrieve the proof once anchored (~10 minutes).
func (c *Client) AnchorAiDecision(ctx context.Context, inputHash, outputHash string, meta *AiDecisionMetadata, opts *AnchorOptions) (*AiDecisionJob, error) {
	if meta == nil {
		return nil, fmt.Errorf("trustbeat: AnchorAiDecision: metadata must not be nil")
	}
	mBody := map[string]any{
		"model_id":        meta.ModelID,
		"system_name":     meta.SystemName,
		"risk_category":   meta.RiskCategory,
		"decision_type":   meta.DecisionType,
		"human_oversight": meta.HumanOversight,
		"time_envelope": map[string]any{
			"started_at":   meta.TimeEnvelope.StartedAt,
			"completed_at": meta.TimeEnvelope.CompletedAt,
		},
	}
	if meta.ModelVersion != "" {
		mBody["model_version"] = meta.ModelVersion
	}
	if meta.OperatorID != "" {
		mBody["operator_id"] = meta.OperatorID
	}
	if meta.DeploymentEnv != "" {
		mBody["deployment_env"] = meta.DeploymentEnv
	}
	if meta.ExternalRef != "" {
		mBody["external_ref"] = meta.ExternalRef
	}
	if meta.DecisionOutcome != "" {
		mBody["decision_outcome"] = meta.DecisionOutcome
	}
	if meta.ModelArtifactHash != "" {
		mBody["model_artifact_hash"] = meta.ModelArtifactHash
	}
	if meta.DataSubjectCategory != "" {
		mBody["data_subject_category"] = meta.DataSubjectCategory
	}
	body := map[string]any{
		"input_hash":  inputHash,
		"output_hash": outputHash,
		"metadata":    mBody,
	}
	if opts != nil && opts.CallbackURL != "" {
		body["callback_url"] = opts.CallbackURL
	}
	var job aiDecisionJobWire
	if err := c.post(ctx, "/ai/decisions/anchor", body, &job); err != nil {
		return nil, err
	}
	return job.toModel(), nil
}

// GetAiDecisionProof retrieves the verification result for a previously submitted AI decision.
// Returns (nil, nil) if the decision is still pending (not yet anchored).
// Returns a *NotFoundError if the tracking ID is unknown.
func (c *Client) GetAiDecisionProof(ctx context.Context, trackingID string) (*AiDecisionProof, error) {
	path := "/ai/decisions/verify/" + url.PathEscape(trackingID)
	var p aiDecisionProofWire
	if err := c.get(ctx, path, &p); err != nil {
		var nfe *NotFoundError
		if errors.As(err, &nfe) && nfe.ErrorCode == "NOT_ANCHORED" {
			return nil, nil
		}
		return nil, err
	}
	return p.toModel(), nil
}

// AnchorAiDecisionWait polls GetAiDecisionProof until the proof is ready, then returns it.
// opts may be nil (defaults: 11-minute timeout, 15-second poll interval).
func (c *Client) AnchorAiDecisionWait(ctx context.Context, trackingID string, opts *WaitOptions) (*AiDecisionProof, error) {
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
		proof, err := c.GetAiDecisionProof(ctx, trackingID)
		if err != nil {
			return nil, err
		}
		if proof != nil {
			return proof, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("trustbeat: AnchorAiDecisionWait timed out after %v for %s", timeout, trackingID)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
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

// ── Signature & certificate verification ─────────────────────────────────────

// VerifySignature validates eIDAS electronic signatures on a document.
// format must be "pades", "cades", or "xades".
// The document bytes are base64-encoded before transmission and never stored.
func (c *Client) VerifySignature(ctx context.Context, document []byte, format string) (*VerificationReport, error) {
	body := map[string]any{
		"document_base64": base64.StdEncoding.EncodeToString(document),
		"format":          format,
	}
	var w verificationReportWire
	if err := c.post(ctx, "/verify/signature", body, &w); err != nil {
		return nil, err
	}
	return w.toModel(), nil
}

// VerifyAndAnchor verifies eIDAS signatures and anchors the verification event.
// Returns immediately (202) with a tracking ID. Use GetVerification to retrieve
// the completed report once anchoring completes (~10 min).
func (c *Client) VerifyAndAnchor(ctx context.Context, document []byte, format string) (*VerificationJob, error) {
	body := map[string]any{
		"document_base64": base64.StdEncoding.EncodeToString(document),
		"format":          format,
	}
	var w verificationJobWire
	if err := c.post(ctx, "/verify/signature/anchored", body, &w); err != nil {
		return nil, err
	}
	return w.toModel(), nil
}

// GetVerification retrieves a saved verification report by tracking ID.
func (c *Client) GetVerification(ctx context.Context, trackingID string) (*VerificationReport, error) {
	var w verificationReportWire
	if err := c.get(ctx, "/verify/"+trackingID, &w); err != nil {
		return nil, err
	}
	return w.toModel(), nil
}

// ValidateCertificate validates a standalone X.509 certificate (DER or PEM)
// against the EU Trusted List — checks chain, revocation, qualified status, and QSCD flag.
func (c *Client) ValidateCertificate(ctx context.Context, certBytes []byte) (*CertificateValidationResult, error) {
	body := map[string]any{
		"certificate_base64": base64.StdEncoding.EncodeToString(certBytes),
	}
	var w certValidationWire
	if err := c.post(ctx, "/validate/certificate", body, &w); err != nil {
		return nil, err
	}
	return w.toModel(), nil
}

type signatureDetailWire struct {
	Index            int     `json:"index"`
	SignerName        *string `json:"signer_name"`
	SignerEmail       *string `json:"signer_email"`
	SigningTime       *string `json:"signing_time"`
	CertSerial        *string `json:"cert_serial"`
	CertFingerprint   *string `json:"cert_fingerprint"`
	CertIssuer        *string `json:"cert_issuer"`
	Qualified         bool    `json:"qualified"`
	OnEutl            bool    `json:"on_eutl"`
	Qscd              bool    `json:"qscd"`
	RevocationStatus  string  `json:"revocation_status"`
	RevocationTime    *string `json:"revocation_time"`
	OcspResponse      *string `json:"ocsp_response"`
	SignatureLevel    string  `json:"signature_level"`
	TimestampPresent  bool    `json:"timestamp_present"`
	TimestampSerial   *string `json:"timestamp_serial"`
	Verdict           string  `json:"verdict"`
}

func derefStr(p *string) string {
	if p == nil { return "" }
	return *p
}

func (w *signatureDetailWire) toModel() SignatureDetail {
	return SignatureDetail{
		Index:            w.Index,
		SignerName:        derefStr(w.SignerName),
		SignerEmail:       derefStr(w.SignerEmail),
		SigningTime:       derefStr(w.SigningTime),
		CertSerial:        derefStr(w.CertSerial),
		CertFingerprint:   derefStr(w.CertFingerprint),
		CertIssuer:        derefStr(w.CertIssuer),
		Qualified:         w.Qualified,
		OnEutl:            w.OnEutl,
		Qscd:              w.Qscd,
		RevocationStatus:  w.RevocationStatus,
		RevocationTime:    derefStr(w.RevocationTime),
		OcspResponse:      derefStr(w.OcspResponse),
		SignatureLevel:    w.SignatureLevel,
		TimestampPresent:  w.TimestampPresent,
		TimestampSerial:   derefStr(w.TimestampSerial),
		Verdict:           w.Verdict,
	}
}

type verificationReportWire struct {
	Verdict      string                `json:"verdict"`
	Signatures   []signatureDetailWire `json:"signatures"`
	DocumentHash string                `json:"document_hash"`
	CheckedAt    string                `json:"checked_at"`
	EutlVersion  *string               `json:"eutl_version"`
	TrackingID   *string               `json:"tracking_id"`
}

func (w *verificationReportWire) toModel() *VerificationReport {
	sigs := make([]SignatureDetail, len(w.Signatures))
	for i, s := range w.Signatures {
		sigs[i] = s.toModel()
	}
	return &VerificationReport{
		Verdict:      w.Verdict,
		Signatures:   sigs,
		DocumentHash: w.DocumentHash,
		CheckedAt:    w.CheckedAt,
		EutlVersion:  derefStr(w.EutlVersion),
		TrackingID:   derefStr(w.TrackingID),
	}
}

type verificationJobWire struct {
	TrackingID   string `json:"tracking_id"`
	DocumentHash string `json:"document_hash"`
	Status       string `json:"status"`
	SubmittedAt  string `json:"submitted_at"`
}

func (w *verificationJobWire) toModel() *VerificationJob {
	return &VerificationJob{
		TrackingID:   w.TrackingID,
		DocumentHash: w.DocumentHash,
		Status:       w.Status,
		SubmittedAt:  w.SubmittedAt,
	}
}

type certValidationWire struct {
	Subject          string   `json:"subject"`
	Issuer           string   `json:"issuer"`
	Serial           string   `json:"serial"`
	NotBefore        string   `json:"not_before"`
	NotAfter         string   `json:"not_after"`
	Qualified        bool     `json:"qualified"`
	OnEutl           bool     `json:"on_eutl"`
	Qscd             bool     `json:"qscd"`
	RevocationStatus string   `json:"revocation_status"`
	RevocationTime   *string  `json:"revocation_time"`
	KeyUsage         []string `json:"key_usage"`
	Valid             bool     `json:"valid"`
	ValidatedAt      string   `json:"validated_at"`
}

func (w *certValidationWire) toModel() *CertificateValidationResult {
	return &CertificateValidationResult{
		Subject:          w.Subject,
		Issuer:           w.Issuer,
		Serial:           w.Serial,
		NotBefore:        w.NotBefore,
		NotAfter:         w.NotAfter,
		Qualified:        w.Qualified,
		OnEutl:           w.OnEutl,
		Qscd:             w.Qscd,
		RevocationStatus: w.RevocationStatus,
		RevocationTime:   derefStr(w.RevocationTime),
		KeyUsage:         w.KeyUsage,
		Valid:             w.Valid,
		ValidatedAt:      w.ValidatedAt,
	}
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
	var errCode string
	var errResp struct {
		Error struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil {
		if errResp.Error.Message != "" {
			msg = errResp.Error.Message
		}
		errCode = errResp.Error.Code
	}
	base := TrustBeatError{Message: msg, Status: status, ErrorCode: errCode}
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
		return &TrustBeatError{Message: msg, Status: status, ErrorCode: errCode}
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

// ── AI Act wire types ─────────────────────────────────────────────────────────

type aiDecisionJobWire struct {
	ID           string `json:"id"`
	InputHash    string `json:"input_hash"`
	OutputHash   string `json:"output_hash"`
	CombinedHash string `json:"combined_hash"`
	Status       string `json:"status"`
	SubmittedAt  string `json:"submitted_at"`
	Overage      bool   `json:"overage"`
}

func (w *aiDecisionJobWire) toModel() *AiDecisionJob {
	return &AiDecisionJob{
		ID:           w.ID,
		InputHash:    w.InputHash,
		OutputHash:   w.OutputHash,
		CombinedHash: w.CombinedHash,
		Status:       w.Status,
		SubmittedAt:  w.SubmittedAt,
		Overage:      w.Overage,
	}
}

type aiTimeEnvelopeWire struct {
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

type aiDecisionMetadataWire struct {
	ModelID             string             `json:"model_id"`
	ModelVersion        string             `json:"model_version"`
	SystemName          string             `json:"system_name"`
	RiskCategory        string             `json:"risk_category"`
	DecisionType        string             `json:"decision_type"`
	HumanOversight      bool               `json:"human_oversight"`
	TimeEnvelope        aiTimeEnvelopeWire `json:"time_envelope"`
	OperatorID          string             `json:"operator_id"`
	DeploymentEnv       string             `json:"deployment_env"`
	ExternalRef         string             `json:"external_ref"`
	DecisionOutcome     string             `json:"decision_outcome"`
	ModelArtifactHash   string             `json:"model_artifact_hash"`
	DataSubjectCategory string             `json:"data_subject_category"`
}

type aiDecisionProofWire struct {
	ID                 string                 `json:"id"`
	InputHash          string                 `json:"input_hash"`
	OutputHash         string                 `json:"output_hash"`
	CombinedHash       string                 `json:"combined_hash"`
	Metadata           aiDecisionMetadataWire `json:"metadata"`
	VerificationStatus string                 `json:"verification_status"`
	AnchoredAt         *string                `json:"anchored_at"`
	Proof              *proofWire             `json:"proof"`
}

func (w *aiDecisionProofWire) toModel() *AiDecisionProof {
	meta := AiDecisionMetadata{
		ModelID:        w.Metadata.ModelID,
		ModelVersion:   w.Metadata.ModelVersion,
		SystemName:     w.Metadata.SystemName,
		RiskCategory:   w.Metadata.RiskCategory,
		DecisionType:   w.Metadata.DecisionType,
		HumanOversight: w.Metadata.HumanOversight,
		TimeEnvelope: AiTimeEnvelope{
			StartedAt:   w.Metadata.TimeEnvelope.StartedAt,
			CompletedAt: w.Metadata.TimeEnvelope.CompletedAt,
		},
		OperatorID:          w.Metadata.OperatorID,
		DeploymentEnv:       w.Metadata.DeploymentEnv,
		ExternalRef:         w.Metadata.ExternalRef,
		DecisionOutcome:     w.Metadata.DecisionOutcome,
		ModelArtifactHash:   w.Metadata.ModelArtifactHash,
		DataSubjectCategory: w.Metadata.DataSubjectCategory,
	}
	p := &AiDecisionProof{
		ID:                 w.ID,
		InputHash:          w.InputHash,
		OutputHash:         w.OutputHash,
		CombinedHash:       w.CombinedHash,
		Metadata:           meta,
		VerificationStatus: w.VerificationStatus,
	}
	if w.AnchoredAt != nil {
		p.AnchoredAt = *w.AnchoredAt
	}
	if w.Proof != nil {
		p.Proof = w.Proof.toModel()
	}
	return p
}

