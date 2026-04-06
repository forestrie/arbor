package custodian

import (
	"errors"
	"strings"
)

// Forestrie operator KMS label keys use the fo- prefix (GCP disallows ":" in label keys).
const (
	ForestrieOperatorLabelPrefix = "fo-"
	ForestrieOwnerIDLabelKey     = "fo-owner_id"
	// ForestrieLogIDLabelKey associates a CryptoKey with a forest log id (value: normalized 32-hex).
	ForestrieLogIDLabelKey = "fo-log_id"
)

// ErrForbiddenUserLabelKey is returned when a user-supplied label key starts with ForestrieOperatorLabelPrefix.
var ErrForbiddenUserLabelKey = errors.New("user label key uses reserved Forestrie operator prefix")

func validateUserLabelKeysNotOperatorPrefix(labels map[string]string) error {
	if len(labels) == 0 {
		return nil
	}
	for k := range labels {
		k = strings.TrimSpace(k)
		if strings.HasPrefix(strings.ToLower(k), ForestrieOperatorLabelPrefix) {
			return ErrForbiddenUserLabelKey
		}
	}
	return nil
}
