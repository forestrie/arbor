package consumer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/arbor/services/ranger"
)

// VerifyObjectHash reads the object from R2 and verifies its SHA256 hash matches the path hash.
func VerifyObjectHash(ctx context.Context, cfg ranger.Config, parsed *ProcessedNotification, httpClient *ranger.HTTPClient, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	if cfg.R2URL == "" {
		return fmt.Errorf("R2_URL not configured")
	}

	s3Client, err := s3.NewClientWithCredentials(
		cfg.R2URL,
		"", // no bearer token; use SigV4
		cfg.AWSAccessKeyID,
		cfg.AWSSecretAccessKey,
		cfg.AWSRegion,
		httpClient,
		logger,
		s3.WithContentSHA256(true),
	)
	if err != nil {
		return fmt.Errorf("build s3 client: %w", err)
	}

	res, err := s3Client.GetObject(ctx, parsed.Path, s3.GetOptions{})
	if err != nil {
		return fmt.Errorf("get object: %w", err)
	}

	content := res.Data

	hasher := sha256.New()
	if _, err := hasher.Write(content); err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	computedHash := hasher.Sum(nil)
	if !bytes.Equal(computedHash, parsed.Hash) {
		return fmt.Errorf(
			"hash mismatch: path has %q, computed %q",
			hex.EncodeToString(parsed.Hash),
			hex.EncodeToString(computedHash),
		)
	}

	return nil
}
