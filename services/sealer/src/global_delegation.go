package sealer

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/forestrie/arbor/services/pkgs/delegationcert"
	"github.com/veraison/go-cose"
)

// DelegationLease is a time-limited, root-signed delegation certificate paired
// with the delegated private key generated locally by sealer.
type DelegationLease struct {
	CertBytes []byte
	Info      *delegationcert.CertificateInfo

	Curve      delegationcert.Curve
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey

	IssuedAt  time.Time
	ExpiresAt time.Time

	// OnchainProof is the univocity publishCheckpoint delegation material
	// issued with the lease (plan-0003); the sealer embeds it in the
	// checkpoint unprotected header for the publisher. Nil when the issuer
	// does not produce it.
	OnchainProof *delegationcert.OnchainDelegationProof

	// Authority binding from the univocity authorize decision (empty when the
	// legacy trust-root path is used). Binds the lease to a specific chain /
	// contract, closing the cross-deployment replay gap (plan-0003).
	RootLogIDHex    string
	ChainID         string
	ContractAddress string
	AuthSource      string // "chain" | "grant"
}

// COSESigner returns a veraison/go-cose Signer + kid + public key to use with
// go-merklelog SignCheckpointReceipt.
func (d *DelegationLease) COSESigner() (cose.Signer, []byte, *ecdsa.PublicKey, error) {
	if d == nil || d.PrivateKey == nil || d.PublicKey == nil {
		return nil, nil, nil, fmt.Errorf("delegation lease missing key material")
	}
	kid, err := kidFromECDSAPublicKey(d.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	switch d.Curve {
	case delegationcert.Secp256r1:
		s, err := cose.NewSigner(cose.AlgorithmES256, d.PrivateKey)
		return s, kid, d.PublicKey, err
	default:
		return nil, nil, nil, fmt.Errorf("unsupported delegation curve %q", d.Curve)
	}
}
