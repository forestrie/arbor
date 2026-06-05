package univocity

import (
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

func parseChainIDPath(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	id, err := strconv.ParseUint(s, 10, 64)
	return id, err == nil
}

func parseContractPath(s string) (common.Address, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(s) != 40 {
		return common.Address{}, false
	}
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return common.Address{}, false
	}
	return common.HexToAddress("0x" + s), true
}

func logIDFromPathValue(s string) ([32]byte, bool) {
	return LogIDFromHex(strings.TrimSpace(s))
}
