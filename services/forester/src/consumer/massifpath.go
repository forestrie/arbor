package consumer

import (
	"fmt"
	"strconv"
	"strings"

	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/google/uuid"
)

// parseV2MassifDataObjectKey parses a v2 massif data object key:
//
//	v2/merklelog/massifs/{height}/{uuid}/{index}.log
//
// It returns ok=false when the key is not a massif data object key.
func parseV2MassifDataObjectKey(key string) (massifHeight uint8, logID massifstorage.LogID, massifIndex uint32, ok bool, err error) {
	clean := strings.TrimPrefix(strings.TrimSpace(key), "/")
	if !strings.HasPrefix(clean, massifstorage.V2MerklelogMassifsPrefix+"/") || !strings.HasSuffix(clean, ".log") {
		return 0, nil, 0, false, nil
	}

	otype, idx, err := massifstorage.ObjectIndexFromPath(clean)
	if err != nil {
		return 0, nil, 0, false, err
	}
	if otype != massifstorage.ObjectMassifData {
		return 0, nil, 0, false, nil
	}

	parts := strings.Split(clean, "/")
	// v2/merklelog/massifs/{height}/{uuid}/{index}.log
	if len(parts) < 6 {
		return 0, nil, 0, false, fmt.Errorf("invalid massif path %q", clean)
	}

	heightU64, err := strconv.ParseUint(parts[3], 10, 8)
	if err != nil {
		return 0, nil, 0, false, fmt.Errorf("parse massifHeight %q: %w", parts[3], err)
	}

	u, err := uuid.Parse(parts[4])
	if err != nil {
		return 0, nil, 0, false, fmt.Errorf("parse logID uuid %q: %w", parts[4], err)
	}

	id := make([]byte, 16)
	copy(id, u[:])

	return uint8(heightU64), massifstorage.LogID(id), idx, true, nil
}

func receiptCacheKeyV1(logID massifstorage.LogID, contentHashHex string) (string, error) {
	u, err := uuid.FromBytes(logID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"ranger/v1/%s/latest/%s",
		u.String(),
		strings.ToLower(contentHashHex),
	), nil
}
