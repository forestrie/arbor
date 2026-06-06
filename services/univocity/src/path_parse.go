package univocity

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
)

func parseChainIDPath(s string) (uint64, bool) {
	id, err := parseChainIDString(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return id, true
}

func parseContractPath(s string) (common.Address, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return common.Address{}, false
	}
	if !strings.HasPrefix(s, "0x") && len(s) == 40 {
		s = "0x" + s
	}
	if !common.IsHexAddress(s) {
		return common.Address{}, false
	}
	return common.HexToAddress(s), true
}

func logIDFromPathValue(s string) (logid.UUID, bool) {
	id, err := logid.ParseSegment(strings.TrimSpace(s))
	if err != nil {
		return logid.Zero, false
	}
	return id, true
}
