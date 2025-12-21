//go:build integration
// +build integration

package tests

import (
	"testing"

	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/forestrie/go-merklelog-provider-testing/mmrtesting"
	"github.com/forestrie/go-merklelog-provider-testing/providers"
)

// TestMassifCommitter_firstMassif covers creation of the first massive blob related conditions.
func TestMassifCommitter_firstMassif(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_firstMassif"))
	factory := NewBuilderFactory(tc)
	providers.StorageMassifCommitterFirstMassifTest(tc, factory)
}

func TestMassifCommitter_massifAddFirst(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_addFirst"))
	factory := NewBuilderFactory(tc)
	providers.StorageMassifCommitterAddFirstTwoLeavesTest(tc, factory)
}

func TestMassifCommitter_massifExtend(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_extend"))
	factory := NewBuilderFactory(tc)
	providers.StorageMassifCommitterExtendAndCommitFirstTest(tc, factory)
}

func TestMassifCommitter_massifComplete(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_complete"))
	factory := NewBuilderFactory(tc)
	providers.StorageMassifCommitterCompleteFirstTest(tc, factory)
}

// TestMassifCommitter_massifoverfillsafe tests that we can't commit a massif blob that has been over filled.
func TestMassifCommitter_massifoverfillsafe(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_overfill"))
	factory := NewBuilderFactory(tc)
	providers.StorageMassifCommitterOverfillSafeTest(tc, factory)
}

func TestMassifCommitter_threemassifs(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_threeMassifs"))
	factory := NewBuilderFactory(tc)
	providers.StorageMassifCommitterThreeMassifsTest(tc, factory)
}

func TestMassifIndexV2_roundtrip(t *testing.T) {
	logger.New("TEST")
	tc := NewTestContext(t, mmrtesting.WithTestLabelPrefix("ranger_r2_indexv2_roundtrip"))
	factory := NewBuilderFactory(tc)
	providers.StorageMassifV2IndexRoundTripTest(tc, factory)
}
