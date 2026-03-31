package storageobjects

import (
	"fmt"
	"net/http"

	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// MapHTTPError translates an HTTP status code into a massifstorage error.
// This unified function handles Get, List, and Put operations.
//
// For Put operations, set failIfExists to true to treat precondition failures
// as existence conflicts (ErrExistsOC) rather than content conflicts
// (ErrContentOC).
func MapHTTPError(statusCode int, failIfExists bool) error {
	switch statusCode {
	case http.StatusNotFound:
		return massifstorage.ErrDoesNotExist
	case http.StatusPreconditionFailed, http.StatusNotModified, http.StatusConflict:
		if failIfExists {
			return massifstorage.ErrExistsOC
		}
		return massifstorage.ErrContentOC
	case http.StatusForbidden, http.StatusUnauthorized,
		http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return massifstorage.ErrNotAvailable
	default:
		// Return nil for unhandled status codes to allow the original error to propagate.
		return nil
	}
}

// wrapWithStatus wraps a sentinel error with HTTP status context while preserving
// errors.Is() compatibility via the %w verb.
func wrapWithStatus(statusCode int, sentinelErr error) error {
	return fmt.Errorf("HTTP %d: %w", statusCode, sentinelErr)
}

// MapGetError translates a low-level storage HTTP error into a massifstorage error
// for GetObject operations. The returned error includes the HTTP status code
// and supports errors.Is() checks against the underlying sentinel error.
func MapGetError(statusCode int, originalErr error) error {
	if mappedErr := MapHTTPError(statusCode, false); mappedErr != nil {
		return wrapWithStatus(statusCode, mappedErr)
	}
	return originalErr
}

// MapListError translates a low-level storage HTTP error into a massifstorage error
// for ListObjects operations. The returned error includes the HTTP status code
// and supports errors.Is() checks against the underlying sentinel error.
func MapListError(statusCode int, originalErr error) error {
	if mappedErr := MapHTTPError(statusCode, false); mappedErr != nil {
		return wrapWithStatus(statusCode, mappedErr)
	}
	return originalErr
}

// MapPutError translates a low-level storage HTTP error into a massifstorage error
// for PutObject operations. The failIfExists flag controls whether certain
// precondition failures are treated as existence conflicts. The returned error
// includes the HTTP status code and supports errors.Is() checks.
func MapPutError(statusCode int, failIfExists bool, originalErr error) error {
	if mappedErr := MapHTTPError(statusCode, failIfExists); mappedErr != nil {
		return wrapWithStatus(statusCode, mappedErr)
	}
	return originalErr
}

// MapDeleteError translates a low-level storage HTTP error into a massifstorage
// error for DeleteObject operations. Note that 404 is treated as success.
// The returned error includes the HTTP status code and supports errors.Is() checks.
func MapDeleteError(statusCode int, originalErr error) error {
	switch statusCode {
	case http.StatusNotFound:
		// Deleting a missing object is treated as success at the storage level.
		return nil
	case http.StatusForbidden, http.StatusUnauthorized,
		http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return wrapWithStatus(statusCode, massifstorage.ErrNotAvailable)
	default:
		return originalErr
	}
}
