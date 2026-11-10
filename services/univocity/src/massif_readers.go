package univocity

import (
	"context"
	"errors"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

var errMassifsNotConfigured = errors.New("log massif storage not configured")

// MassifReaders opens readers over logs' massifs in the MMR log bucket
// (R2_URL), where univocity scans an owner's leaf table for create grants.
type MassifReaders interface {
	// Massif returns a reader over logID's massifs as they are now.
	Massif(ctx context.Context, logID logid.UUID) (massifs.ObjectReader, error)
	MassifHeight() uint8
}

type factoryMassifReaders struct {
	factory *merklelog.Factory
	height  uint8
}

// NewMassifReaders reads massifs of the given height through factory.
func NewMassifReaders(factory *merklelog.Factory, height uint8) MassifReaders {
	return factoryMassifReaders{factory: factory, height: height}
}

// Massif returns a fresh store on each call: a store caches the head massif,
// and a scan must see leaves appended since the last one.
func (r factoryMassifReaders) Massif(ctx context.Context, logID logid.UUID) (massifs.ObjectReader, error) {
	s, err := r.factory.NewStore(massifstorage.LogID(logID[:]))
	if err != nil {
		return nil, err
	}
	if err := s.SelectLog(ctx, massifstorage.LogID(logID[:])); err != nil {
		return nil, err
	}
	return s, nil
}

func (r factoryMassifReaders) MassifHeight() uint8 { return r.height }
