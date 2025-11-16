package consumer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/forestrie/arbor/services/ranger"
)

// VerifyObjectHash reads the object from R2 and verifies its SHA256 hash matches the path hash.
func VerifyObjectHash(ctx context.Context, cfg ranger.Config, parsed *ParsedNotification, httpClient *ranger.HTTPClient, logger *slog.Logger) error {
	_ = logger

	if cfg.R2PublicURL == "" {
		return fmt.Errorf("R2_PUBLIC_URL not configured")
	}

	objectURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(cfg.R2PublicURL, "/"), parsed.Path)

	req, err := http.NewRequest("GET", objectURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to fetch object: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch object: status %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read object content: %w", err)
	}

	hasher := sha256.New()
	if _, err := hasher.Write(content); err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	computedHash := hasher.Sum(nil)
	if !bytes.Equal(computedHash, parsed.Hash) {
		return fmt.Errorf("hash mismatch: path has %q, computed %q", hex.EncodeToString(parsed.Hash), hex.EncodeToString(computedHash))
	}

	return nil
}
