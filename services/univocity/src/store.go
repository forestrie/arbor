package univocity

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// ErrStoreNotConfigured indicates the owned grant store is unavailable.
var ErrStoreNotConfigured = errors.New("grant store not configured")

// Store is the univocity-owned object store: forest genesis documents, the
// per-forest creation-grant collection, and the global logId->R index.
//
// Layout (S3/R2):
//   - genesis: forest/{hex64(R)}/genesis.cbor
//   - grants:  forest/{hex64(R)}/grants/{hex64(subject)}.cbor
//   - index:   index/log/{hex64(subject)}        (32-byte R payload)
type Store interface {
	GetGenesis(ctx context.Context, r [32]byte) ([]byte, error)
	PutGenesisIfAbsent(ctx context.Context, r [32]byte, body []byte) (created bool, err error)
	GetGrant(ctx context.Context, r, subject [32]byte) ([]byte, error)
	PutGrant(ctx context.Context, r, subject [32]byte, body []byte) error
	IndexGet(ctx context.Context, subject [32]byte) (r [32]byte, found bool, err error)
	IndexCreate(ctx context.Context, subject, r [32]byte) (created bool, existing [32]byte, err error)
	DeleteGenesis(ctx context.Context, r [32]byte) error
	DeleteGrant(ctx context.Context, r, subject [32]byte) error
	DeleteIndex(ctx context.Context, subject [32]byte) error
	ListForests(ctx context.Context) ([][32]byte, error)
}

const maxStoredObject = 256 * 1024

// s3Store is the S3/R2-backed Store implementation.
type s3Store struct {
	client *s3.Client
}

// NewS3Store wraps an s3.Client as the owned grant store.
func NewS3Store(client *s3.Client) Store {
	return &s3Store{client: client}
}

func hex64(id [32]byte) string { return hex.EncodeToString(id[:]) }

func genesisKey(r [32]byte) string { return "forest/" + hex64(r) + "/genesis.cbor" }

func grantKey(r, subject [32]byte) string {
	return "forest/" + hex64(r) + "/grants/" + hex64(subject) + ".cbor"
}

func indexKey(subject [32]byte) string { return "index/log/" + hex64(subject) }

func (s *s3Store) GetGenesis(ctx context.Context, r [32]byte) ([]byte, error) {
	return s.get(ctx, genesisKey(r))
}

func (s *s3Store) PutGenesisIfAbsent(
	ctx context.Context,
	r [32]byte,
	body []byte,
) (bool, error) {
	_, err := s.client.PutObject(ctx, genesisKey(r), body, s3.PutOptions{
		ContentType:  "application/cbor",
		IfNoneMatch:  "*",
		FailIfExists: true,
	})
	if err != nil {
		if errors.Is(err, massifstorage.ErrExistsOC) {
			return false, nil
		}
		return false, fmt.Errorf("put genesis: %w", err)
	}
	return true, nil
}

func (s *s3Store) GetGrant(ctx context.Context, r, subject [32]byte) ([]byte, error) {
	return s.get(ctx, grantKey(r, subject))
}

func (s *s3Store) PutGrant(ctx context.Context, r, subject [32]byte, body []byte) error {
	_, err := s.client.PutObject(ctx, grantKey(r, subject), body, s3.PutOptions{
		ContentType: "application/cbor",
	})
	if err != nil {
		return fmt.Errorf("put grant: %w", err)
	}
	return nil
}

func (s *s3Store) IndexGet(ctx context.Context, subject [32]byte) ([32]byte, bool, error) {
	body, err := s.get(ctx, indexKey(subject))
	if err != nil {
		if errors.Is(err, massifstorage.ErrDoesNotExist) {
			return [32]byte{}, false, nil
		}
		return [32]byte{}, false, err
	}
	var r [32]byte
	if len(body) != 32 {
		return [32]byte{}, false, fmt.Errorf("index payload must be 32 bytes, got %d", len(body))
	}
	copy(r[:], body)
	return r, true, nil
}

func (s *s3Store) IndexCreate(
	ctx context.Context,
	subject, r [32]byte,
) (bool, [32]byte, error) {
	_, err := s.client.PutObject(ctx, indexKey(subject), r[:], s3.PutOptions{
		ContentType:  "application/octet-stream",
		IfNoneMatch:  "*",
		FailIfExists: true,
	})
	if err == nil {
		return true, r, nil
	}
	if !errors.Is(err, massifstorage.ErrExistsOC) {
		return false, [32]byte{}, fmt.Errorf("create index: %w", err)
	}
	existing, found, getErr := s.IndexGet(ctx, subject)
	if getErr != nil {
		return false, [32]byte{}, getErr
	}
	if !found {
		return false, [32]byte{}, errors.New("index create conflict but entry absent")
	}
	return false, existing, nil
}

func (s *s3Store) DeleteGenesis(ctx context.Context, r [32]byte) error {
	return s.client.DeleteObject(ctx, genesisKey(r))
}

func (s *s3Store) DeleteGrant(ctx context.Context, r, subject [32]byte) error {
	return s.client.DeleteObject(ctx, grantKey(r, subject))
}

func (s *s3Store) DeleteIndex(ctx context.Context, subject [32]byte) error {
	return s.client.DeleteObject(ctx, indexKey(subject))
}

// ListForests enumerates forest genesis objects (forest/{hex64}/genesis.cbor).
func (s *s3Store) ListForests(ctx context.Context) ([][32]byte, error) {
	var out [][32]byte
	continuation := ""
	for {
		page, err := s.client.ListObjects(ctx, "forest/", continuation, 1000)
		if err != nil {
			return nil, fmt.Errorf("list forests: %w", err)
		}
		for _, obj := range page.Objects {
			hexStr, ok := parseForestKey(obj.Key)
			if !ok {
				continue
			}
			r, ok := wireLogIDFromHex64(hexStr)
			if !ok {
				continue
			}
			out = append(out, r)
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		continuation = page.NextContinuationToken
	}
	return out, nil
}

func (s *s3Store) get(ctx context.Context, key string) ([]byte, error) {
	res, err := s.client.GetObject(ctx, key, s3.GetOptions{RangeLength: -1})
	if err != nil {
		return nil, err
	}
	body := res.Data
	if len(body) > maxStoredObject {
		body = body[:maxStoredObject]
	}
	return body, nil
}
