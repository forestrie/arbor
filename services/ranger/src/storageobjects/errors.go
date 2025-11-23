package storageobjects

import (
	"net/http"

	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// MapHTTPError translates an HTTP status code into a massifstorage error.
// This unified function handles Get, List, and Put operations.
// For Put operations, set failIfExists to true to treat precondition failures
// as existence conflicts (ErrExistsOC) rather than content conflicts (ErrContentOC).
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
		// Return nil for unhandled status codes to allow the original error to propagate
		return nil
	}
}

// MapGetError translates a low-level storage HTTP error into a massifstorage error
// for GetObject operations.
func MapGetError(statusCode int, originalErr error) error {
	if mappedErr := MapHTTPError(statusCode, false); mappedErr != nil {
		return mappedErr
	}
	return originalErr
}

// MapListError translates a low-level storage HTTP error into a massifstorage error
// for ListObjects operations.
func MapListError(statusCode int, originalErr error) error {
	if mappedErr := MapHTTPError(statusCode, false); mappedErr != nil {
		return mappedErr
	}
	return originalErr
}

// MapPutError translates a low-level storage HTTP error into a massifstorage error
// for PutObject operations. The failIfExists flag controls whether certain
// precondition failures are treated as existence conflicts.
func MapPutError(statusCode int, failIfExists bool, originalErr error) error {
	if mappedErr := MapHTTPError(statusCode, failIfExists); mappedErr != nil {
		return mappedErr
	}
	return originalErr
}

// MapDeleteError translates a low-level storage HTTP error into a massifstorage
// error for DeleteObject operations. Note that 404 is treated as success.
func MapDeleteError(statusCode int, originalErr error) error {
	switch statusCode {
	case http.StatusNotFound:
		// Deleting a missing object is treated as success at the storage level.
		return nil
	case http.StatusForbidden, http.StatusUnauthorized,
		http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return massifstorage.ErrNotAvailable
	default:
		return originalErr
	}
}

