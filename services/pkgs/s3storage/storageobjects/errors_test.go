package storageobjects

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

func TestMapPutError_StatusMappingsWithFailIfExists(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		failIfExists bool
		want         error
	}{
		{
			name:         "NotFound maps to ErrDoesNotExist",
			status:       http.StatusNotFound,
			failIfExists: false,
			want:         massifstorage.ErrDoesNotExist,
		},
		{
			name:         "PreconditionFailed with failIfExists maps to ErrExistsOC",
			status:       http.StatusPreconditionFailed,
			failIfExists: true,
			want:         massifstorage.ErrExistsOC,
		},
		{
			name:         "PreconditionFailed without failIfExists maps to ErrContentOC",
			status:       http.StatusPreconditionFailed,
			failIfExists: false,
			want:         massifstorage.ErrContentOC,
		},
		{
			name:         "Conflict with failIfExists maps to ErrExistsOC",
			status:       http.StatusConflict,
			failIfExists: true,
			want:         massifstorage.ErrExistsOC,
		},
		{
			name:         "Conflict without failIfExists maps to ErrContentOC",
			status:       http.StatusConflict,
			failIfExists: false,
			want:         massifstorage.ErrContentOC,
		},
		{
			name:         "Forbidden maps to ErrNotAvailable",
			status:       http.StatusForbidden,
			failIfExists: false,
			want:         massifstorage.ErrNotAvailable,
		},
		{
			name:         "TooManyRequests maps to ErrNotAvailable",
			status:       http.StatusTooManyRequests,
			failIfExists: false,
			want:         massifstorage.ErrNotAvailable,
		},
		{
			name:         "ServiceUnavailable maps to ErrNotAvailable",
			status:       http.StatusServiceUnavailable,
			failIfExists: true,
			want:         massifstorage.ErrNotAvailable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := fmt.Errorf("original error")
			got := MapPutError(tc.status, tc.failIfExists, orig)
			if !errors.Is(got, tc.want) {
				t.Fatalf("MapPutError(%d, %v) = %v, want %v", tc.status, tc.failIfExists, got, tc.want)
			}
		})
	}
}

func TestMapPutError_UnhandledStatusReturnsOriginalError(t *testing.T) {
	orig := fmt.Errorf("original error")
	got := MapPutError(http.StatusInternalServerError, false, orig)
	if got != orig {
		t.Fatalf("expected original error to be returned, got %v", got)
	}
}

func TestMapError_IncludesHTTPStatusCode(t *testing.T) {
	cases := []struct {
		name       string
		mapFunc    func() error
		wantStatus int
		wantErr    error
	}{
		{
			name:       "MapListError includes 403 status",
			mapFunc:    func() error { return MapListError(http.StatusForbidden, nil) },
			wantStatus: 403,
			wantErr:    massifstorage.ErrNotAvailable,
		},
		{
			name:       "MapGetError includes 401 status",
			mapFunc:    func() error { return MapGetError(http.StatusUnauthorized, nil) },
			wantStatus: 401,
			wantErr:    massifstorage.ErrNotAvailable,
		},
		{
			name:       "MapPutError includes 404 status",
			mapFunc:    func() error { return MapPutError(http.StatusNotFound, false, nil) },
			wantStatus: 404,
			wantErr:    massifstorage.ErrDoesNotExist,
		},
		{
			name:       "MapDeleteError includes 429 status",
			mapFunc:    func() error { return MapDeleteError(http.StatusTooManyRequests, nil) },
			wantStatus: 429,
			wantErr:    massifstorage.ErrNotAvailable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.mapFunc()

			// Check that errors.Is still works
			if !errors.Is(got, tc.wantErr) {
				t.Errorf("errors.Is(%v, %v) = false, want true", got, tc.wantErr)
			}

			// Check that the error message includes the HTTP status code
			wantPrefix := fmt.Sprintf("HTTP %d:", tc.wantStatus)
			if got == nil || len(got.Error()) < len(wantPrefix) {
				t.Errorf("error message too short: %v", got)
			} else if got.Error()[:len(wantPrefix)] != wantPrefix {
				t.Errorf("error message = %q, want prefix %q", got.Error(), wantPrefix)
			}
		})
	}
}
