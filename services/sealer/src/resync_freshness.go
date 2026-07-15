package sealer

import (
	"github.com/forestrie/go-merklelog/massifs"
)

// headMMRSizeFromObjectSize computes a log's current head MMR size from the head
// massif object's byte size, without downloading the massif. It mirrors
// go-merklelog's own RangeCount (Start.FirstIndex + Count): the first MMR index
// of massif `headIndex` at `height` plus the number of 32-byte log entries the
// object holds beyond its fixed log-start offset.
//
// The layout offset is taken from go-merklelog itself (MassifContext.LogStart on
// a synthesized current-version Start header) rather than reimplemented, so a
// future format change is inherited, not silently diverged.
func headMMRSizeFromObjectSize(height uint8, headIndex uint32, objectSize int64) uint64 {
	mc := massifs.MassifContext{
		Start: massifs.MassifStart{
			Version:      massifs.MassifCurrentVersion,
			MassifHeight: height,
		},
	}
	logStart := mc.LogStart()
	first := massifs.MassifFirstLeaf(height, headIndex)
	if objectSize < 0 || uint64(objectSize) <= logStart {
		return first
	}
	return first + (uint64(objectSize)-logStart)/massifs.LogEntryBytes
}

// truncateForLog returns a printable, length-bounded preview of a response body
// for error logs.
func truncateForLog(b []byte, max int) string {
	if max <= 0 || len(b) == 0 {
		return ""
	}
	s := string(b)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
