package signer

import (
	"context"
	"fmt"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// KeyManagementClient is the subset of KMS client we need (for testing with a mock).
type KeyManagementClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error)
}

// GCPKeySigner implements KeySigner using GCP Cloud KMS AsymmetricSign.
type GCPKeySigner struct {
	client KeyManagementClient
}

// NewGCPKeySigner returns a KeySigner that uses the given KMS client.
func NewGCPKeySigner(client KeyManagementClient) *GCPKeySigner {
	return &GCPKeySigner{client: client}
}

// Sign signs digest with the key at keyID. digest must be 32 bytes (SHA-256).
func (g *GCPKeySigner) Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	req := &kmspb.AsymmetricSignRequest{
		Name:   keyID,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
	}
	resp, err := g.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("kms asymmetric sign: %w", err)
	}
	if resp.Signature == nil {
		return nil, fmt.Errorf("kms returned nil signature")
	}
	return resp.Signature, nil
}
