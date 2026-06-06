package sealer

import (
	"fmt"
	"strings"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

// logIDAPISegment converts a 32-char hex log id (or canonical UUID segment) to
// the dashed UUID path segment expected by univocity HTTP APIs.
func logIDAPISegment(logIdHex string) (string, error) {
	s := strings.TrimSpace(logIdHex)
	if s == "" {
		return "", fmt.Errorf("log id is empty")
	}
	u, err := logid.ParseSegment(s)
	if err != nil {
		return "", fmt.Errorf("invalid log id segment: %w", err)
	}
	return u.String(), nil
}
