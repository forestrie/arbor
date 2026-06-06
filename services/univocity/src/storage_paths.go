package univocity

import "strings"

const (
	forestGenesisPrefix = "forests/forest/"
	forestGenesisSuffix = "/genesis.cbor"
)

func forestGenesisObjectKey(uuid string) string {
	return forestGenesisPrefix + uuid + forestGenesisSuffix
}

// parseForestGenesisKey extracts the uuid-R segment from forests/forest/{uuid}/genesis.cbor.
func parseForestGenesisKey(key string) (uuid string, ok bool) {
	if !strings.HasPrefix(key, forestGenesisPrefix) || !strings.HasSuffix(key, forestGenesisSuffix) {
		return "", false
	}
	uuid = strings.TrimPrefix(key, forestGenesisPrefix)
	uuid = strings.TrimSuffix(uuid, forestGenesisSuffix)
	if uuid == "" || strings.Contains(uuid, "/") {
		return "", false
	}
	return uuid, true
}
