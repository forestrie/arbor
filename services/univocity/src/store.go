package univocity

import (
	"context"
	"errors"
	"fmt"

	"github.com/forestrie/arbor/services/pkgs/logid"
	"github.com/forestrie/arbor/services/pkgs/s3storage/s3"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// ErrStoreNotConfigured indicates the owned grant store is unavailable.
var ErrStoreNotConfigured = errors.New("grant store not configured")

// Store is the univocity-owned object store: forest genesis documents, the
// per-forest creation-grant collection, and the global logId->R index.
//
// Layout (S3/R2):
//   - genesis: forests/forest/{uuid-R}/genesis.cbor
//   - grants:  forests/forest/{uuid-R}/grants/auth-log|data-log/{uuid-subject}.cbor
//   - index:   forests/index/forest/{uuid-subject}  (ASCII UUID of R)
type Store interface {
	GetGenesis(ctx context.Context, r logid.UUID) ([]byte, error)
	PutGenesisIfAbsent(ctx context.Context, r logid.UUID, body []byte) (created bool, err error)
	GetGrant(ctx context.Context, r, subject logid.UUID) ([]byte, error)
	PutGrant(ctx context.Context, r, subject logid.UUID, class GrantClass, body []byte) error
	IndexGet(ctx context.Context, subject logid.UUID) (r logid.UUID, found bool, err error)
	IndexCreate(ctx context.Context, subject, r logid.UUID) (created bool, existing logid.UUID, err error)
	DeleteGenesis(ctx context.Context, r logid.UUID) error
	DeleteGrant(ctx context.Context, r, subject logid.UUID) error
	DeleteIndex(ctx context.Context, subject logid.UUID) error
	ListForests(ctx context.Context) ([]logid.UUID, error)
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

func genesisKey(r logid.UUID) string {
	return "forests/forest/" + r.String() + "/genesis.cbor"
}

func grantKey(r, subject logid.UUID, class GrantClass) string {
	return "forests/forest/" + r.String() + "/grants/" + grantClassDir(class) + "/" + subject.String() + ".cbor"
}

func indexKey(subject logid.UUID) string {
	return "forests/index/forest/" + subject.String()
}

func (s *s3Store) GetGenesis(ctx context.Context, r logid.UUID) ([]byte, error) {
	return s.get(ctx, genesisKey(r))
}

func (s *s3Store) PutGenesisIfAbsent(
	ctx context.Context,
	r logid.UUID,
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

func (s *s3Store) GetGrant(ctx context.Context, r, subject logid.UUID) ([]byte, error) {
	for _, class := range []GrantClass{GrantClassAuthLog, GrantClassDataLog} {
		body, err := s.get(ctx, grantKey(r, subject, class))
		if err == nil {
			return body, nil
		}
		if !errors.Is(err, massifstorage.ErrDoesNotExist) {
			return nil, err
		}
	}
	return nil, massifstorage.ErrDoesNotExist
}

func (s *s3Store) PutGrant(
	ctx context.Context,
	r, subject logid.UUID,
	class GrantClass,
	body []byte,
) error {
	if grantClassDir(class) == "" {
		return fmt.Errorf("invalid grant class")
	}
	_, err := s.client.PutObject(ctx, grantKey(r, subject, class), body, s3.PutOptions{
		ContentType: "application/cbor",
	})
	if err != nil {
		return fmt.Errorf("put grant: %w", err)
	}
	return nil
}

func (s *s3Store) IndexGet(ctx context.Context, subject logid.UUID) (logid.UUID, bool, error) {
	body, err := s.get(ctx, indexKey(subject))
	if err != nil {
		if errors.Is(err, massifstorage.ErrDoesNotExist) {
			return logid.Zero, false, nil
		}
		return logid.Zero, false, err
	}
	r, err := logid.ParseIndexBody(body)
	if err != nil {
		return logid.Zero, false, fmt.Errorf("index payload: %w", err)
	}
	return r, true, nil
}

func (s *s3Store) IndexCreate(
	ctx context.Context,
	subject, r logid.UUID,
) (bool, logid.UUID, error) {
	payload := []byte(r.String())
	_, err := s.client.PutObject(ctx, indexKey(subject), payload, s3.PutOptions{
		ContentType:  "text/plain; charset=utf-8",
		IfNoneMatch:  "*",
		FailIfExists: true,
	})
	if err == nil {
		return true, r, nil
	}
	if !errors.Is(err, massifstorage.ErrExistsOC) {
		return false, logid.Zero, fmt.Errorf("create index: %w", err)
	}
	existing, found, getErr := s.IndexGet(ctx, subject)
	if getErr != nil {
		return false, logid.Zero, getErr
	}
	if !found {
		return false, logid.Zero, errors.New("index create conflict but entry absent")
	}
	return false, existing, nil
}

func (s *s3Store) DeleteGenesis(ctx context.Context, r logid.UUID) error {
	return s.client.DeleteObject(ctx, genesisKey(r))
}

func (s *s3Store) DeleteGrant(ctx context.Context, r, subject logid.UUID) error {
	var firstErr error
	for _, class := range []GrantClass{GrantClassAuthLog, GrantClassDataLog} {
		if err := s.client.DeleteObject(ctx, grantKey(r, subject, class)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *s3Store) DeleteIndex(ctx context.Context, subject logid.UUID) error {
	return s.client.DeleteObject(ctx, indexKey(subject))
}

// ListForests enumerates forest genesis objects (forests/forest/{uuid}/genesis.cbor).
func (s *s3Store) ListForests(ctx context.Context) ([]logid.UUID, error) {
	var out []logid.UUID
	continuation := ""
	for {
		page, err := s.client.ListObjects(ctx, "forests/forest/", continuation, 1000)
		if err != nil {
			return nil, fmt.Errorf("list forests: %w", err)
		}
		for _, obj := range page.Objects {
			uuidStr, ok := parseForestGenesisKey(obj.Key)
			if !ok {
				continue
			}
			id, err := logid.ParseUUIDString(uuidStr)
			if err != nil {
				continue
			}
			out = append(out, id)
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
