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
	// MMRStart and MMREnd are payload labels 3 and 4: the inclusive MMR
	// index range the delegation authorizes. Both are required and are
	// full-width uint64; ParseCertificate rejects a certificate that omits
	// either or carries any other CBOR type (ErrMMRRangeBound), because an
	// absent bound must not read as 0 and a float is not an index.
	MMRStart              uint64
	MMREnd                uint64
	PayloadIssuedAt       string
	PayloadExpiresAt      string
	PayloadIssuedAtUnix   uint64
	PayloadExpiresAtUnix  uint64
	PayloadDelegatedCurve string
	SignatureSize         int
}
