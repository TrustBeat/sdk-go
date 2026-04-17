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
	ModelVersion   string         // optional — additional version string
	OperatorID     string         // optional — identifier of the operator/process
	DeploymentEnv  string         // optional — "production", "staging", "testing"
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

// TimestampResult holds a dedicated (non-batched) RFC 3161 qualified timestamp.
// One credit is consumed per call. Token is the raw DER-encoded TimeStampToken.
type TimestampResult struct {
	ID            string
	Hash          string
	HashAlgorithm string
	Token         []byte // raw DER-encoded RFC 3161 TimeStampToken
	TokenFormat   string
	TSASerial     string
	Provider      string
	IssuedAt      string // ISO 8601
	ClientRef     string
	Description   string
}
