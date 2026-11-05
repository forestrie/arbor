package ingress

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The ack's firstLeafIndex is a full uint64 on the wire. canopy's
// forestrie-ingress decodes it with a strict uint64 check, so it must be
// CBOR major type 0 in shortest form, never a float.
//
// The golden uses massif height 33: a massif of one-based height h holds
// 2^(h-1) leaves, and canopy rejects a leaf whose massif index exceeds
// 2^32-1, so 2^64-1 is only reachable at h >= 33.

// ackGoldenUint64MaxHex is EncodeAckRequest(ackGoldenUint64Max()).
// canopy's ack handler tests decode the same bytes; change both together.
const ackGoldenUint64MaxHex = "a7" +
	"656c696d697401" + // "limit": 1
	"656c6f6749645010" + "1112131415161718191a1b1c1d1e1f" + // "logId": h'10..1f'
	"65736571486901" + // "seqHi": 1
	"657365714c6f01" + // "seqLo": 1
	"6b6c65617365457870697279" + "1b0000018bcfe5dd30" + // "leaseExpiry": 1700000030000
	"6c6d6173736966486569676874" + "1821" + // "massifHeight": 33
	"6e66697273744c656166496e646578" + "1bffffffffffffffff" // "firstLeafIndex": 2^64-1

// ackGoldenLeaseExpiry is a pull lease in ms, past 2^32 as real ones are.
const ackGoldenLeaseExpiry uint64 = 1_700_000_030_000

func ackGoldenUint64Max() AckRequest {
	logID := make([]byte, 16)
	for i := range logID {
		logID[i] = byte(0x10 + i)
	}
	return AckRequest{
		LogId:          logID,
		SeqLo:          1,
		SeqHi:          1,
		LeaseExpiry:    ackGoldenLeaseExpiry,
		Limit:          1,
		FirstLeafIndex: math.MaxUint64,
		MassifHeight:   33,
	}
}

func TestEncodeAckRequest_GoldenUint64Max(t *testing.T) {
	want, err := hex.DecodeString(ackGoldenUint64MaxHex)
	if err != nil {
		t.Fatalf("golden hex: %v", err)
	}
	got, err := EncodeAckRequest(ackGoldenUint64Max())
	if err != nil {
		t.Fatalf("EncodeAckRequest: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ack bytes\n got %x\nwant %x", got, want)
	}
}

func TestEncodeAckRequest_FirstLeafIndexIsShortestUint(t *testing.T) {
	cases := []struct {
		name  string
		index uint64
		want  []byte // encoded firstLeafIndex value
	}{
		{"zero", 0, []byte{0x00}},
		{"one-byte", 255, []byte{0x18, 0xff}},
		{"four-byte max", math.MaxUint32, []byte{0x1a, 0xff, 0xff, 0xff, 0xff}},
		{"first eight-byte", 1 << 32, []byte{0x1b, 0, 0, 0, 1, 0, 0, 0, 0}},
		{"above 2^53", 1<<53 + 1, []byte{0x1b, 0, 0x20, 0, 0, 0, 0, 0, 1}},
		{"uint64 max", math.MaxUint64, []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	key := mustCBOR(t, "firstLeafIndex")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := ackGoldenUint64Max()
			req.FirstLeafIndex = tc.index
			data, err := EncodeAckRequest(req)
			if err != nil {
				t.Fatalf("EncodeAckRequest: %v", err)
			}

			// firstLeafIndex sorts last (longest key), so its value ends the map.
			if !bytes.HasSuffix(data, append(append([]byte{}, key...), tc.want...)) {
				t.Fatalf("firstLeafIndex not encoded as %x: %x", tc.want, data)
			}

			var back AckRequest
			if err := cbor.Unmarshal(data, &back); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if back.FirstLeafIndex != tc.index {
				t.Fatalf("round trip: got %d, want %d", back.FirstLeafIndex, tc.index)
			}
		})
	}
}
