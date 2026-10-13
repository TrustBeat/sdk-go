package trustbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// ── Signature Preservation (not yet available: the API answers 404 until launch) ──

// SignaturePreservationRecord is a preserved signed file (/v1/signature-preservation).
//
// Status is "pending" (queued for the next anchoring cycle), "anchored" (its RFC 4998 evidence
// record is being made) or "preserved" (the evidence record exists). Signatures is nil in a list;
// each entry is the API's object (signer, EU DSS indication, qualification).
type SignaturePreservationRecord struct {
	ID             string  `json:"id"`
	Status         string  `json:"status"`
	CreatedAt      string  `json:"created_at"`
	ClientRef      *string `json:"client_ref"`
	SignatureCount int     `json:"signature_count"`
	Container      struct {
		Format string `json:"format"`
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	} `json:"container"`
	// PEO.SHA256 is the SHA-256 of the Preservation Evidence Object — the anchored leaf.
	PEO struct {
		SHA256 string `json:"sha256"`
		SHA512 string `json:"sha512"`
	} `json:"peo"`
	Preservation struct {
		Profile       string `json:"profile"`
		ProfileStatus string `json:"profile_status"`
		PreserveUntil string `json:"preserve_until"`
	} `json:"preservation"`
	EvidenceRecord struct {
		Status      string  `json:"status"` // "pending" | "ready"
		DownloadURL *string `json:"download_url"`
	} `json:"evidence_record"`
	Signatures []map[string]any `json:"signatures"`
}

// SignaturePreservationStep is one step of a verification report.
type SignaturePreservationStep struct {
	Step      int      `json:"step"`
	Name      string   `json:"name"` // file | binding | signature | chain | timestamps | qualification | evidence-record
	Title     string   `json:"title"`
	Result    string   `json:"result"` // passed | failed | indeterminate | not-applicable
	CheckedBy []string `json:"checked_by"`
	Details   []string `json:"details"`
}

// SignaturePreservationReport is the report of POST /v1/signature-preservation/{id}/verify.
// Result is "passed", "failed" (a step failed) or "indeterminate" (a step could not be decided).
// Raw is the full JSON report (signatures now and at preservation, evidence-record time-stamps).
type SignaturePreservationReport struct {
	RecordID string                      `json:"record_id"`
	Result   string                      `json:"result"`
	Claim    string                      `json:"claim"`
	Steps    []SignaturePreservationStep `json:"steps"`
	Raw      json.RawMessage             `json:"-"`
}

// PreserveOptions are optional fields of PreserveSignatures.
type PreserveOptions struct {
	// ClientRef is your own reference for the record (at most 256 characters).
	ClientRef string
}

// PreserveSignatures preserves the signatures of a signed file.
//
// submission is the JSON that `trustbeat-signature extract <file>` writes. It holds the signatures
// and the digests binding them to the file; the signed file itself never reaches TrustBeat, and
// this SDK does not read signed files. Counts as one anchor against the monthly quota. opts may be nil.
func (c *Client) PreserveSignatures(ctx context.Context, submission []byte, opts *PreserveOptions) (*SignaturePreservationRecord, error) {
	body, err := submissionBody(submission)
	if err != nil {
		return nil, err
	}
	path := "/signature-preservation"
	if opts != nil && opts.ClientRef != "" {
		path += "?client_ref=" + url.QueryEscape(opts.ClientRef)
	}
	var rec SignaturePreservationRecord
	if err := c.post(ctx, path, body, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// GetSignaturePreservation returns one preserved signed file, with its signatures and their EU DSS findings.
func (c *Client) GetSignaturePreservation(ctx context.Context, recordID string) (*SignaturePreservationRecord, error) {
	var rec SignaturePreservationRecord
	if err := c.get(ctx, "/signature-preservation/"+url.PathEscape(recordID), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListSignaturePreservations returns the account's preserved signed files, newest first, without
// their signatures. limit 0 means the API's default.
func (c *Client) ListSignaturePreservations(ctx context.Context, limit int) ([]SignaturePreservationRecord, error) {
	path := "/signature-preservation"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var out struct {
		Records []SignaturePreservationRecord `json:"records"`
	}
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return out.Records, nil
}

// DownloadSignaturePreservationPackage returns the record's package (ZIP) for verification without
// TrustBeat. Keep it next to the original file; `trustbeat-signature verify <file> --package <zip>`
// checks both offline.
func (c *Client) DownloadSignaturePreservationPackage(ctx context.Context, recordID string) ([]byte, error) {
	raw, _, err := c.getRaw(ctx, "/signature-preservation/"+url.PathEscape(recordID)+"/package")
	return raw, err
}

// VerifySignaturePreservation verifies a signed file presented now against its record: the
// eight-step report. submission is `trustbeat-signature extract` of the file presented now. A file
// that does not match gives a report with failed steps, not an error. Not counted against the quota.
func (c *Client) VerifySignaturePreservation(ctx context.Context, recordID string, submission []byte) (*SignaturePreservationReport, error) {
	body, err := submissionBody(submission)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.post(ctx, "/signature-preservation/"+url.PathEscape(recordID)+"/verify", body, &raw); err != nil {
		return nil, err
	}
	var rep SignaturePreservationReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("trustbeat: unmarshal response: %w", err)
	}
	rep.Raw = raw
	return &rep, nil
}

// VerifySignaturePreservationPDF returns the same report as VerifySignaturePreservation, as a PDF.
func (c *Client) VerifySignaturePreservationPDF(ctx context.Context, recordID string, submission []byte) ([]byte, error) {
	body, err := submissionBody(submission)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/signature-preservation/"+url.PathEscape(recordID)+"/verify?format=pdf", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("trustbeat: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "trustbeat-go/"+sdkVersion)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trustbeat: request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("trustbeat: read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, mapHTTPError(resp.StatusCode, raw, resp.Header)
	}
	return raw, nil
}

// submissionBody checks that submission is a JSON object and returns it unchanged.
func submissionBody(submission []byte) (json.RawMessage, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(submission, &probe); err != nil || probe == nil {
		return nil, errors.New("trustbeat: a submission is a JSON object, as written by `trustbeat-signature extract`")
	}
	return json.RawMessage(submission), nil
}
