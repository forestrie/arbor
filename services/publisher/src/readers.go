package publisher

import (
	"log/slog"
	"sync"

	"github.com/forestrie/arbor/services/pkgs/s3storage/merklelog"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

// Readers builds R2-backed massif/checkpoint object readers for a log. The S3
// factory bakes in the massif height, so factories are cached per height (a
// forest uses one height across all its logs).
type Readers struct {
	baseURL, token       string
	akid, secret, region string
	doer                 s3.HTTPDoer
	logger               *slog.Logger

	mu        sync.Mutex
	factories map[uint8]*merklelog.Factory
}

// NewReaders constructs the reader builder from the publisher config. doer is
// the shared pooled HTTP client (its Do signature satisfies s3.HTTPDoer).
func NewReaders(cfg Config, doer s3.HTTPDoer, logger *slog.Logger) *Readers {
	return &Readers{
		baseURL:   cfg.R2URL,
		token:     cfg.R2Token,
		akid:      cfg.AWSAccessKeyID,
		secret:    cfg.AWSSecretAccessKey,
		region:    cfg.AWSRegion,
		doer:      doer,
		logger:    logger,
		factories: make(map[uint8]*merklelog.Factory),
	}
}

func (r *Readers) factory(massifHeight uint8) (*merklelog.Factory, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.factories[massifHeight]; ok {
		return f, nil
	}
	f, err := merklelog.NewS3FactoryWithCredentials(
		r.baseURL, r.token, r.akid, r.secret, r.region, massifHeight, r.doer, r.logger)
	if err != nil {
		return nil, err
	}
	r.factories[massifHeight] = f
	return f, nil
}

// Massif returns a massifs.ObjectReader over the R2 objects for logID at the
// given massif height. NewStore selects the log cache, so the returned reader
// is ready for GetCheckpoint / GetMassifContext.
func (r *Readers) Massif(logID logid.UUID, massifHeight uint8) (massifs.ObjectReader, error) {
	f, err := r.factory(massifHeight)
	if err != nil {
		return nil, err
	}
	id := logID
	return f.NewStore(massifstorage.LogID(id[:]))
}
