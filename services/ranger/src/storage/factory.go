package storage

import (
	"fmt"

	"log/slog"

	"github.com/forestrie/arbor/services/ranger/r2"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Factory constructs R2-backed merklelog writers for specific logs.
type Factory struct {
	client *r2.Client
	logger *slog.Logger
}

// NewFactory initialises a Factory using the shared R2 REST client.
func NewFactory(baseURL, token string, doer r2.HTTPDoer, logger *slog.Logger) (*Factory, error) {
	if logger == nil {
		logger = slog.Default()
	}

	client, err := r2.NewClient(baseURL, token, doer, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to build r2 client: %w", err)
	}

	return &Factory{
		client: client,
		logger: logger,
	}, nil
}

// NewReplacer returns a massifs.ObjectWriter implementation for the provided logID.
func (f *Factory) NewReplacer(logID massifstorage.LogID) (*Replacer, error) {
	return NewReplacer(f.client, logID, f.logger)
}

// NewStore returns an ObjectReaderWriter implementation backed by R2 for the given logID.
func (f *Factory) NewStore(logID massifstorage.LogID) (*Store, error) {
	return NewStore(f.client, logID, f.logger)
}
