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