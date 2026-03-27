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
