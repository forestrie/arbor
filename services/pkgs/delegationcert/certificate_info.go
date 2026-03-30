package delegationcert

// CertificateInfo summarizes a parsed delegation COSE_Sign1 (forestrie.delegation profile).
type CertificateInfo struct {
	CertSHA256             string
	CertSize               int
	ProtectedAlg           int64
	ProtectedCty           string
	ProtectedKidHex        string
	PayloadDelegationIDHex string
	PayloadLogID           string
	PayloadLogIDPrefix     string
	PayloadMmrStart        string
	PayloadMmrEnd          string
	PayloadIssuedAt        string
	PayloadExpiresAt       string
	PayloadIssuedAtUnix    uint64
	PayloadExpiresAtUnix   uint64
	PayloadDelegatedCurve  string
	SignatureSize          int
}
