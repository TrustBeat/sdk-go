package trustbeat

// ProofStep is one step in a Merkle inclusion proof path.
type ProofStep struct {
	// Sibling is the hex-encoded SHA-256 hash of the sibling node.
	Sibling string
	// Side is the position of the sibling: "left" or "right".
	Side string
}

// AnchorJob is returned immediately (HTTP 202) when a hash is enqueued for anchoring.
// Use GetProof or AnchorWait to retrieve the proof once the batch has been committed.
type AnchorJob struct {
	ID            string
	Hash          string
	HashAlgorithm string
	Status        string // "pending" at creation
	SubmittedAt   string // ISO 8601
	Overage       bool   // true when the monthly quota was already exceeded
}

// AnchorProof is the full Merkle inclusion proof returned once the batch has been anchored.
// Token contains the raw DER-encoded RFC 3161 qualified timestamp token. Save it as a .tsr
// file to verify with standard TSA tools (e.g., openssl ts -verify).
type AnchorProof struct {
	ID            string
	Hash          string // SHA-256 hex digest of the anchored content
	HashAlgorithm string
	BatchID       string
	LeafIndex     int
	MerkleRoot    string      // hex
	ProofPath     []ProofStep // Merkle path from leaf to root
	Token         []byte      // raw DER-encoded RFC 3161 TimeStampToken
	TokenFormat   string
	TSASerial     string
	Provider      string
	AnchoredAt    string // ISO 8601
	ClientRef     string // empty if not set
	Description   string // empty if not set
}

// BatchSubmission is returned by AnchorBatch. The SubmissionID groups all items
// so their status and proofs can be retrieved together.
type BatchSubmission struct {
	SubmissionID string
	Items        []*AnchorJob
}

// BatchStatus is returned by GetBatchStatus.
type BatchStatus struct {
	SubmissionID string
	Total        int
	Anchored     int
	Pending      int
}

// ── AI Act Audit models ───────────────────────────────────────────────────────

// AiTimeEnvelope holds the start and end times of a single AI inference call.
type AiTimeEnvelope struct {
	StartedAt   string // ISO 8601 — when inference started
	CompletedAt string // ISO 8601 — when inference completed
}

// AiDecisionMetadata describes an AI decision for EU AI Act Article 12 anchoring.
// ModelID, SystemName, RiskCategory, DecisionType, HumanOversight, and TimeEnvelope are required.
type AiDecisionMetadata struct {
	ModelID        string         // model identifier, e.g. "claude-3-5-sonnet-20241022"
	SystemName     string         // AI system name, e.g. "cv-screening-v2"
	RiskCategory   string         // AI Act Annex III category, e.g. "employment"
	DecisionType   string         // "classification", "ranking", "recommendation", etc.
	HumanOversight bool           // true if human oversight (AI Act Article 14) was in place
	TimeEnvelope   AiTimeEnvelope
	ModelVersion        string         // optional — additional version string
	OperatorID          string         // optional — identifier of the operator/process
	DeploymentEnv       string         // optional — "production", "staging", "testing"
	// Art. 12 traceability fields — optional, recommended for full compliance
	ExternalRef         string         // optional — operator's own case/record ID
	DecisionOutcome     string         // optional — semantic result, e.g. "rejected"
	ModelArtifactHash   string         // optional — SHA-256 of deployed model weights
	DataSubjectCategory string         // optional — e.g. "job_applicant"
}

// AiDecisionJob is returned immediately (HTTP 202) when an AI decision is enqueued.
// Use GetAiDecisionProof or AnchorAiDecisionWait to retrieve the proof.
type AiDecisionJob struct {
	ID           string
	InputHash    string
	OutputHash   string
	CombinedHash string // SHA-256(input_bytes ‖ output_bytes ‖ UTF-8(JCS(metadata)))
	Status       string // "pending"
	SubmittedAt  string // ISO 8601
	Overage      bool
}

// AiDecisionProof is the verification result returned once the AI decision has been anchored.
// VerificationStatus is "VERIFIED" when the Merkle proof is valid and the combined hash matches.
type AiDecisionProof struct {
	ID                 string
	InputHash          string
	OutputHash         string
	CombinedHash       string
	Metadata           AiDecisionMetadata
	VerificationStatus string // "VERIFIED" | "FAILED"
	AnchoredAt         string // ISO 8601; empty if not yet available
	Proof              *AnchorProof
}

// ── Verification models ───────────────────────────────────────────────────────

// SignatureDetail holds the per-signature result within a VerificationReport.
type SignatureDetail struct {
	Index            int
	SignerName        string
	SignerEmail       string
	SigningTime       string
	CertSerial        string
	CertFingerprint   string
	CertIssuer        string
	Qualified         bool
	OnEutl            bool
	Qscd              bool
	RevocationStatus  string // "GOOD" | "REVOKED"
	RevocationTime    string
	OcspResponse      string
	SignatureLevel    string // e.g. "B-LT", "B-LTA"
	TimestampPresent  bool
	TimestampSerial   string
	Verdict           string // SignatureVerdict value
}

// VerificationReport is the full eIDAS signature verification report returned by VerifySignature.
// TrackingID is set after the report is saved; use with GetVerification.
type VerificationReport struct {
	Verdict      string
	Signatures   []SignatureDetail
	DocumentHash string // SHA-256 hex of the submitted document
	CheckedAt    string // ISO 8601
	EutlVersion  string
	TrackingID   string
}

// VerificationJob is returned immediately (HTTP 202) when VerifyAndAnchor is called.
type VerificationJob struct {
	TrackingID   string
	DocumentHash string
	Status       string // "pending"
	SubmittedAt  string // ISO 8601
}

// CertificateValidationResult is returned by ValidateCertificate.
type CertificateValidationResult struct {
	Subject          string
	Issuer           string
	Serial           string
	NotBefore        string
	NotAfter         string
	Qualified        bool
	OnEutl           bool
	Qscd             bool
	RevocationStatus string
	RevocationTime   string
	KeyUsage         []string
	Valid             bool
	ValidatedAt      string // ISO 8601
}

// ── Audit Trail ───────────────────────────────────────────────────────────────

// AuditProofStep is one step in an audit event Merkle inclusion proof.
type AuditProofStep struct {
	Sibling string // hex-encoded SHA-256 hash of the sibling node
	Side    string // "left" or "right"
}

// AuditEvent is a single audit event as returned by ListAuditEvents.
type AuditEvent struct {
	EventID       string
	TrailCategory string
	Actor         string
	Action        string
	Ts            string // ISO 8601 — when the event occurred
	ReceivedAt    string // ISO 8601 — when TrustBeat received it
	Anchored      bool
	System        string
	Resource      string
}

// AuditEventProof is the full Merkle inclusion proof for an anchored audit event.
type AuditEventProof struct {
	EventID       string
	CanonicalHash string
	BatchID       string
	LeafIndex     int
	MerklePath    []AuditProofStep
	AnchoredAt    string // ISO 8601
}

// AuditExportJob is returned immediately (202) when ExportAuditEvents is called.
// Poll until Status is "ready" or "failed".
type AuditExportJob struct {
	JobID      string
	Status     string // "pending" | "processing" | "ready" | "failed"
	EventCount int
	Error      string
}


// ── Tamper-Evident Logs (NIS2) ─────────────────────────────────────────────────

// LogSource identifies the log source being anchored. URI is required.
type LogSource struct {
	URI       string // file path, S3 URI, syslog identifier, etc.
	Name      string // optional — human-readable name
	SizeBytes int64  // optional — size in bytes (0 = omit)
}

// LogTimeEnvelope is the time window covered by the anchored log.
type LogTimeEnvelope struct {
	StartAt string // ISO 8601
	EndAt   string // ISO 8601
}

// LogSourceIdentity identifies the system that emitted the log (all fields optional).
type LogSourceIdentity struct {
	SystemUUID      string
	CloudInstanceID string
	Hostname        string
	ServiceName     string
	TenantID        string
}

// LogMetadata is sealed alongside a log hash for NIS2 Article 21 anchoring. The
// server computes combined_hash = SHA-256(log_hash_bytes ‖ UTF-8(JCS(metadata))).
// LogSource.URI and SourceIdentity are required; TimeEnvelope is optional (nil).
type LogMetadata struct {
	LogSource      LogSource
	SourceIdentity LogSourceIdentity
	TimeEnvelope   *LogTimeEnvelope
}

// LogAnchorJob is returned immediately (202) when a log hash is enqueued.
type LogAnchorJob struct {
	ID           string
	LogHash      string
	CombinedHash string
	Status       string // "pending"
	SubmittedAt  string // ISO 8601
	Overage      bool
	Label        string
}

// LogStatus is the lightweight status of a log anchor submission.
type LogStatus struct {
	ID          string
	Status      string // "pending" | "anchored"
	SubmittedAt string
	AnchoredAt  string // empty until anchored
}

// LogAnchorListItem is a single log anchor submission from ListLogs.
type LogAnchorListItem struct {
	ID           string
	LogHash      string
	Status       string
	SubmittedAt  string
	LogSourceURI string
	AnchoredAt   string
	ServiceName  string
	Label        string
}

// LogProof is the verification result for an anchored log. VerificationStatus is
// "VERIFIED" when the Merkle proof is valid and the combined hash matches.
type LogProof struct {
	ID                 string
	LogHash            string
	Metadata           LogMetadata
	CombinedHash       string
	VerificationStatus string // "VERIFIED" | "FAILED"
	ArchiveStampsCount int
	AnchoredAt         string
	Proof              *AnchorProof
	FailureReasons     []string
}
