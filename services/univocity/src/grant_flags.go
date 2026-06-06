package univocity

import "errors"

// GrantClass is the auth-log vs data-log namespace for stored grants.
type GrantClass int

const (
	GrantClassAuthLog GrantClass = iota + 1
	GrantClassDataLog
)

var errGrantClassAmbiguous = errors.New("grant flags must set GF_AUTH_LOG or GF_DATA_LOG exclusively")

// grantClassFromFlags classifies a grant for storage routing (byte 7 low nibble).
func grantClassFromFlags(flags []byte) (GrantClass, error) {
	if len(flags) < 8 {
		return 0, errGrantClassAmbiguous
	}
	low := flags[7]
	auth := (low & 0x01) != 0
	data := (low & 0x02) != 0
	switch {
	case auth && !data:
		return GrantClassAuthLog, nil
	case data && !auth:
		return GrantClassDataLog, nil
	default:
		return 0, errGrantClassAmbiguous
	}
}

func grantClassDir(class GrantClass) string {
	switch class {
	case GrantClassAuthLog:
		return "auth-log"
	case GrantClassDataLog:
		return "data-log"
	default:
		return ""
	}
}
