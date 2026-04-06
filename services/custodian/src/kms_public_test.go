package custodian

import (
	"fmt"
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
	wrapped := fmt.Errorf("outer: %w", status.Error(codes.NotFound, "nested"))
	if !kmsErrIsNotFound(wrapped) {
		t.Error("expected true for wrapped grpc NotFound")
	}
}

func TestKmsErrPublicKeyUnavailable(t *testing.T) {
	if kmsErrPublicKeyUnavailable(nil) {
		t.Error("expected false for nil")
	}
	if !kmsErrPublicKeyUnavailable(errKmsNoEnabledSigningVersion) {
		t.Error("expected true when no ENABLED signing version (e.g. post-destroy)")
	}
	if !kmsErrPublicKeyUnavailable(status.Error(codes.NotFound, "gone")) {
		t.Error("expected true for NotFound")
	}
	if kmsErrPublicKeyUnavailable(status.Error(codes.Internal, "kms")) {
		t.Error("expected false for Internal")
	}
}
