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
	sdkVersion     = "0.2.0"
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
		"hash_algorithm": "SHA-256",
	}
	applyOpts(body, opts)

	var job anchorJobWire
	if err := c.post(ctx, "/anchor", body, &job); err != nil {
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
		items[i] = map[string]any{"hash": h, "hash_algorithm": "SHA-256"}
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
	if err := c.post(ctx, "/anchor/batch", body, &resp); err != nil {
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
	if err := c.get(ctx, "/anchor/batch/"+url.PathEscape(submissionID)+"/status", &resp); err != nil {
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
	if err := c.get(ctx, "/anchor/batch/"+url.PathEscape(submissionID)+"/proofs", &resp); err != nil {
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
	path := "/anchor/" + url.PathEscape(trackingID) + "/proof"
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
	// Before anchoring the API returns 200 with verification_status "PENDING"
	// and no proof — treat that as "not ready yet" so pollers keep waiting.
	if p.VerificationStatus == "PENDING" {
		return nil, nil
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

// ── Audit Trail ───────────────────────────────────────────────────────────────

type auditEventWire struct {
	EventID       string  `json:"event_id"`
	TrailCategory string  `json:"trail_category"`
	Actor         string  `json:"actor"`
	Action        string  `json:"action"`
	Ts            string  `json:"ts"`
	ReceivedAt    string  `json:"received_at"`
	Anchored      bool    `json:"anchored"`
	System        *string `json:"system"`
	Resource      *string `json:"resource"`
}

func (w *auditEventWire) toModel() AuditEvent {
	return AuditEvent{
		EventID: w.EventID, TrailCategory: w.TrailCategory, Actor: w.Actor,
		Action: w.Action, Ts: w.Ts, ReceivedAt: w.ReceivedAt, Anchored: w.Anchored,
		System: derefStr(w.System), Resource: derefStr(w.Resource),
	}
}

type auditProofStepWire struct {
	Sibling string `json:"sibling"`
	Side    string `json:"side"`
}

type auditEventProofWire struct {
	EventID       string               `json:"event_id"`
	CanonicalHash string               `json:"canonical_hash"`
	BatchID       string               `json:"batch_id"`
	LeafIndex     int                  `json:"leaf_index"`
	MerklePath    []auditProofStepWire `json:"merkle_path"`
	AnchoredAt    string               `json:"anchored_at"`
	Status        string               `json:"status"` // "pending" when not yet anchored
}

func (w *auditEventProofWire) toModel() *AuditEventProof {
	path := make([]AuditProofStep, len(w.MerklePath))
	for i, s := range w.MerklePath {
		path[i] = AuditProofStep{Sibling: s.Sibling, Side: s.Side}
	}
	return &AuditEventProof{
		EventID: w.EventID, CanonicalHash: w.CanonicalHash, BatchID: w.BatchID,
		LeafIndex: w.LeafIndex, MerklePath: path, AnchoredAt: w.AnchoredAt,
	}
}

type auditExportJobWire struct {
	JobID      string `json:"job_id"`
	Status     string `json:"status"`
	EventCount int    `json:"event_count"`
	Error      string `json:"error"`
}

// SubmitAuditEvent submits a single audit event for tamper-evident Merkle anchoring.
// Returns the eventID immediately (202 Accepted).
func (c *Client) SubmitAuditEvent(ctx context.Context, trailCategory, actor, action, ts string, opts map[string]any) (string, error) {
	body := map[string]any{
		"trail_category": trailCategory,
		"actor":          actor,
		"action":         action,
		"ts":             ts,
	}
	for k, v := range opts {
		body[k] = v
	}
	var out struct {
		EventID string `json:"event_id"`
	}
	if err := c.post(ctx, "/audit/events", body, &out); err != nil {
		return "", err
	}
	return out.EventID, nil
}

// SubmitAuditEvents submits up to 1,000 audit events in a single batch request.
// Each event is a map with the same keys accepted by SubmitAuditEvent
// (trail_category, actor, action, ts, and optional fields such as metadata).
// Returns the event IDs in submission order.
func (c *Client) SubmitAuditEvents(ctx context.Context, events []map[string]any) ([]string, error) {
	var out struct {
		EventIDs []string `json:"event_ids"`
	}
	// The API decodes the body as a bare JSON array of events — send it directly.
	if err := c.post(ctx, "/audit/events/batch", events, &out); err != nil {
		return nil, err
	}
	return out.EventIDs, nil
}

// GetAuditEventProof fetches the Merkle inclusion proof for an anchored audit event.
// Returns nil, nil if the event is not yet anchored (still pending the next batch cycle).
func (c *Client) GetAuditEventProof(ctx context.Context, eventID string) (*AuditEventProof, error) {
	var w auditEventProofWire
	if err := c.get(ctx, "/audit/events/"+eventID+"/proof", &w); err != nil {
		return nil, err
	}
	if w.Status == "pending" {
		return nil, nil
	}
	return w.toModel(), nil
}

// ListAuditEvents queries audit events with optional URL query parameters.
// Pass nil or empty params map to list all events on page 1.
func (c *Client) ListAuditEvents(ctx context.Context, params url.Values) ([]AuditEvent, error) {
	path := "/audit/events"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	var out struct {
		Events []auditEventWire `json:"events"`
	}
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	events := make([]AuditEvent, len(out.Events))
	for i := range out.Events {
		events[i] = out.Events[i].toModel()
	}
	return events, nil
}

// ExportAuditEvents exports audit events as a court-admissible ZIP package and
// returns the raw ZIP bytes. Blocks until the export job completes.
//
// opts must contain "from" and "to" (ISO 8601 strings, required by the API) and
// may contain "trail_category".
func (c *Client) ExportAuditEvents(ctx context.Context, opts map[string]string) ([]byte, error) {
	if opts["from"] == "" || opts["to"] == "" {
		return nil, errors.New("trustbeat: ExportAuditEvents requires \"from\" and \"to\" in opts")
	}
	body := make(map[string]any, len(opts))
	for k, v := range opts {
		body[k] = v
	}
	var jobResp struct {
		JobID string `json:"job_id"`
	}
	if err := c.post(ctx, "/audit/export", body, &jobResp); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Minute)
	for {
		raw, ct, err := c.getRaw(ctx, "/audit/export/"+jobResp.JobID)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(ct, "application/zip") {
			return raw, nil
		}
		var status auditExportJobWire
		if err := json.Unmarshal(raw, &status); err != nil {
			return nil, fmt.Errorf("trustbeat: parse export status: %w", err)
		}
		if status.Status == "failed" {
			return nil, errors.New("trustbeat: export failed: " + status.Error)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("trustbeat: export job %s timed out", jobResp.JobID)
		}
		time.Sleep(3 * time.Second)
	}
}

// ── Low-level HTTP ────────────────────────────────────────────────────────────

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// getRaw returns the raw response bytes and content-type header.
func (c *Client) getRaw(ctx context.Context, path string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, "", fmt.Errorf("trustbeat: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "trustbeat-go/"+sdkVersion)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("trustbeat: request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("trustbeat: read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", mapHTTPError(resp.StatusCode, raw)
	}
	return raw, resp.Header.Get("Content-Type"), nil
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


// ── Tamper-Evident Logs (NIS2) ──────────────────────────────────────────────────

// AnchorLog submits a log hash for NIS2 Article 21 tamper-evident anchoring.
// Returns immediately (202); the log is anchored in the next batch (~10 min).
// Pass label="" to omit the optional cross-reference label.
func (c *Client) AnchorLog(ctx context.Context, logHash string, meta *LogMetadata, label string) (*LogAnchorJob, error) {
	if meta == nil {
		return nil, fmt.Errorf("trustbeat: AnchorLog: metadata must not be nil")
	}
	body := map[string]any{
		"log_hash": logHash,
		"metadata": logMetadataToBody(meta),
	}
	if label != "" {
		body["label"] = label
	}
	var w logAnchorJobWire
	if err := c.post(ctx, "/logs/anchor", body, &w); err != nil {
		return nil, err
	}
	return w.toModel(), nil
}

// GetLogProof fetches the verification result for a log anchor.
// Returns (nil, nil) while the log is still pending (verification_status "PENDING").
// Returns a *NotFoundError if the tracking ID is unknown.
func (c *Client) GetLogProof(ctx context.Context, trackingID string) (*LogProof, error) {
	var w logProofWire
	if err := c.get(ctx, "/logs/verify/"+url.PathEscape(trackingID), &w); err != nil {
		return nil, err
	}
	if w.VerificationStatus == "PENDING" {
		return nil, nil
	}
	return w.toModel(), nil
}

// GetLogStatus returns the lightweight status of a log anchor submission.
func (c *Client) GetLogStatus(ctx context.Context, trackingID string) (*LogStatus, error) {
	var w logStatusWire
	if err := c.get(ctx, "/logs/"+url.PathEscape(trackingID)+"/status", &w); err != nil {
		return nil, err
	}
	return w.toModel(), nil
}

// ListLogs lists recent log anchor submissions. params may carry "status"
// ("pending"/"anchored"), "from", and "to" (ISO 8601); pass nil for all.
func (c *Client) ListLogs(ctx context.Context, params url.Values) ([]LogAnchorListItem, error) {
	path := "/logs"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	var out struct {
		Logs []logAnchorListItemWire `json:"logs"`
	}
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	items := make([]LogAnchorListItem, len(out.Logs))
	for i := range out.Logs {
		items[i] = out.Logs[i].toModel()
	}
	return items, nil
}

// ExportLog downloads a portable NIS2 log proof bundle (bundle_type
// "trustbeat.log.proof") and returns the raw JSON bundle bytes.
func (c *Client) ExportLog(ctx context.Context, trackingID string) ([]byte, error) {
	raw, _, err := c.getRaw(ctx, "/logs/"+url.PathEscape(trackingID)+"/export")
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// AnchorLogWait polls GetLogProof until the log is anchored, then returns the proof.
// opts may be nil (defaults: 11-minute timeout, 15-second poll interval).
func (c *Client) AnchorLogWait(ctx context.Context, trackingID string, opts *WaitOptions) (*LogProof, error) {
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
		proof, err := c.GetLogProof(ctx, trackingID)
		if err != nil {
			return nil, err
		}
		if proof != nil {
			return proof, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("trustbeat: AnchorLogWait timed out after %v for %s", timeout, trackingID)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

func logMetadataToBody(meta *LogMetadata) map[string]any {
	src := map[string]any{"uri": meta.LogSource.URI}
	if meta.LogSource.Name != "" {
		src["name"] = meta.LogSource.Name
	}
	if meta.LogSource.SizeBytes != 0 {
		src["size_bytes"] = meta.LogSource.SizeBytes
	}
	ident := map[string]any{}
	if meta.SourceIdentity.SystemUUID != "" {
		ident["system_uuid"] = meta.SourceIdentity.SystemUUID
	}
	if meta.SourceIdentity.CloudInstanceID != "" {
		ident["cloud_instance_id"] = meta.SourceIdentity.CloudInstanceID
	}
	if meta.SourceIdentity.Hostname != "" {
		ident["hostname"] = meta.SourceIdentity.Hostname
	}
	if meta.SourceIdentity.ServiceName != "" {
		ident["service_name"] = meta.SourceIdentity.ServiceName
	}
	if meta.SourceIdentity.TenantID != "" {
		ident["tenant_id"] = meta.SourceIdentity.TenantID
	}
	out := map[string]any{"log_source": src, "source_identity": ident}
	if meta.TimeEnvelope != nil {
		out["time_envelope"] = map[string]any{
			"start_at": meta.TimeEnvelope.StartAt,
			"end_at":   meta.TimeEnvelope.EndAt,
		}
	}
	return out
}

// ── Tamper-Evident Logs wire types ──────────────────────────────────────────────

type logAnchorJobWire struct {
	ID           string  `json:"id"`
	LogHash      string  `json:"log_hash"`
	CombinedHash string  `json:"combined_hash"`
	Status       string  `json:"status"`
	SubmittedAt  string  `json:"submitted_at"`
	Overage      bool    `json:"overage"`
	Label        *string `json:"label"`
}

func (w *logAnchorJobWire) toModel() *LogAnchorJob {
	j := &LogAnchorJob{
		ID: w.ID, LogHash: w.LogHash, CombinedHash: w.CombinedHash,
		Status: w.Status, SubmittedAt: w.SubmittedAt, Overage: w.Overage,
	}
	if w.Label != nil {
		j.Label = *w.Label
	}
	return j
}

type logStatusWire struct {
	ID          string  `json:"id"`
	Status      string  `json:"status"`
	SubmittedAt string  `json:"submitted_at"`
	AnchoredAt  *string `json:"anchored_at"`
}

func (w *logStatusWire) toModel() *LogStatus {
	s := &LogStatus{ID: w.ID, Status: w.Status, SubmittedAt: w.SubmittedAt}
	if w.AnchoredAt != nil {
		s.AnchoredAt = *w.AnchoredAt
	}
	return s
}

type logAnchorListItemWire struct {
	ID           string  `json:"id"`
	LogHash      string  `json:"log_hash"`
	Status       string  `json:"status"`
	SubmittedAt  string  `json:"submitted_at"`
	LogSourceURI string  `json:"log_source_uri"`
	AnchoredAt   *string `json:"anchored_at"`
	ServiceName  *string `json:"service_name"`
	Label        *string `json:"label"`
}

func (w *logAnchorListItemWire) toModel() LogAnchorListItem {
	it := LogAnchorListItem{
		ID: w.ID, LogHash: w.LogHash, Status: w.Status,
		SubmittedAt: w.SubmittedAt, LogSourceURI: w.LogSourceURI,
	}
	if w.AnchoredAt != nil {
		it.AnchoredAt = *w.AnchoredAt
	}
	if w.ServiceName != nil {
		it.ServiceName = *w.ServiceName
	}
	if w.Label != nil {
		it.Label = *w.Label
	}
	return it
}

type logSourceWire struct {
	URI       string `json:"uri"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
}

type logTimeEnvelopeWire struct {
	StartAt string `json:"start_at"`
	EndAt   string `json:"end_at"`
}

type logSourceIdentityWire struct {
	SystemUUID      string `json:"system_uuid"`
	CloudInstanceID string `json:"cloud_instance_id"`
	Hostname        string `json:"hostname"`
	ServiceName     string `json:"service_name"`
	TenantID        string `json:"tenant_id"`
}

type logMetadataWire struct {
	LogSource      logSourceWire         `json:"log_source"`
	SourceIdentity logSourceIdentityWire `json:"source_identity"`
	TimeEnvelope   *logTimeEnvelopeWire  `json:"time_envelope"`
}

type logProofWire struct {
	ID                 string          `json:"id"`
	LogHash            string          `json:"log_hash"`
	Metadata           logMetadataWire `json:"metadata"`
	CombinedHash       string          `json:"combined_hash"`
	VerificationStatus string          `json:"verification_status"`
	ArchiveStampsCount int             `json:"archive_stamps_count"`
	AnchoredAt         *string         `json:"anchored_at"`
	Proof              *proofWire      `json:"proof"`
	FailureReasons     []string        `json:"failure_reasons"`
}

func (w *logProofWire) toModel() *LogProof {
	meta := LogMetadata{
		LogSource: LogSource{
			URI:       w.Metadata.LogSource.URI,
			Name:      w.Metadata.LogSource.Name,
			SizeBytes: w.Metadata.LogSource.SizeBytes,
		},
		SourceIdentity: LogSourceIdentity{
			SystemUUID:      w.Metadata.SourceIdentity.SystemUUID,
			CloudInstanceID: w.Metadata.SourceIdentity.CloudInstanceID,
			Hostname:        w.Metadata.SourceIdentity.Hostname,
			ServiceName:     w.Metadata.SourceIdentity.ServiceName,
			TenantID:        w.Metadata.SourceIdentity.TenantID,
		},
	}
	if w.Metadata.TimeEnvelope != nil {
		meta.TimeEnvelope = &LogTimeEnvelope{
			StartAt: w.Metadata.TimeEnvelope.StartAt,
			EndAt:   w.Metadata.TimeEnvelope.EndAt,
		}
	}
	p := &LogProof{
		ID: w.ID, LogHash: w.LogHash, Metadata: meta,
		CombinedHash: w.CombinedHash, VerificationStatus: w.VerificationStatus,
		ArchiveStampsCount: w.ArchiveStampsCount, FailureReasons: w.FailureReasons,
	}
	if w.AnchoredAt != nil {
		p.AnchoredAt = *w.AnchoredAt
	}
	if w.Proof != nil {
		p.Proof = w.Proof.toModel()
	}
	return p
}
