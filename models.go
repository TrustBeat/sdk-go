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

