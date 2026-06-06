package univocity

import "github.com/forestrie/arbor/services/pkgs/logid"

func testLogID(n byte) logid.UUID {
	var u logid.UUID
	u[15] = n
	return u
}

func authLogFlags() []byte {
	f := make([]byte, 8)
	f[7] = 0x01
	return f
}
