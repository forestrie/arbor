package custodian

import (
	"testing"

	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestKmsErrIsNotFound(t *testing.T) {
	if kmsErrIsNotFound(nil) {
		t.Error("expected false for nil")
	}
	if !kmsErrIsNotFound(status.Error(codes.NotFound, "missing")) {
		t.Error("expected true for grpc NotFound")
	}
	if kmsErrIsNotFound(status.Error(codes.PermissionDenied, "no")) {
		t.Error("expected false for PermissionDenied")
	}
	if !kmsErrIsNotFound(&googleapi.Error{Code: 404}) {
		t.Error("expected true for googleapi 404")
	}
}
