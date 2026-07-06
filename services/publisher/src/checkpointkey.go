package publisher

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

// CheckpointKey is a parsed checkpoint object key.
type CheckpointKey struct {
	LogID        logid.UUID
	MassifHeight uint8
	MassifIndex  uint32
}

// ParseCheckpointKey parses a checkpoint R2 object key of the form
//
//	v2/merklelog/checkpoints/{massifHeight}/{uuid}/{massifIndex}.sth
//
// The publisher queue is notified on the v2/merklelog/checkpoints/ prefix; this
// extracts the logId, massif height and massif index the one-shot core needs.
func ParseCheckpointKey(key string) (CheckpointKey, error) {
	clean := strings.TrimPrefix(path.Clean(key), "/")
	parts := strings.Split(clean, "/")
	// v2 / merklelog / checkpoints / {height} / {uuid} / {index}.sth
	if len(parts) < 6 {
		return CheckpointKey{}, fmt.Errorf(
			"invalid checkpoint key: expected v2/merklelog/checkpoints/{height}/{uuid}/{index}.sth, got %d segments", len(parts))
	}
	if parts[0] != "v2" || parts[1] != "merklelog" || parts[2] != "checkpoints" {
		return CheckpointKey{}, fmt.Errorf("invalid checkpoint key prefix: %q", strings.Join(parts[:3], "/"))
	}

	h64, err := strconv.ParseUint(parts[3], 10, 8)
	if err != nil || h64 == 0 {
		return CheckpointKey{}, fmt.Errorf("invalid massif height %q", parts[3])
	}

	logID, err := logid.ParseUUIDString(parts[4])
	if err != nil {
		return CheckpointKey{}, fmt.Errorf("invalid logId segment %q: %w", parts[4], err)
	}

	name := parts[len(parts)-1]
	base := strings.TrimSuffix(name, ".sth")
	if base == name {
		return CheckpointKey{}, fmt.Errorf("checkpoint object %q is not a .sth", name)
	}
	idx, err := strconv.ParseUint(base, 10, 32)
	if err != nil {
		return CheckpointKey{}, fmt.Errorf("invalid massif index %q: %w", base, err)
	}

	return CheckpointKey{LogID: logID, MassifHeight: uint8(h64), MassifIndex: uint32(idx)}, nil
}
