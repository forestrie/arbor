package tests

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/forestrie/arbor/services/ranger/consumer"
	"github.com/forestrie/go-merklelog/massifs/storage"
	"github.com/google/uuid"
)

func makeQueueMessage1(
	tc *TestContext,
	logID storage.LogID,
	fenceIndex uint64,
	content []byte,
) consumer.QueueMessage {
	var err error
	t := tc.GetT()
	g := tc.GetG()

	logIDUUID, err := uuid.FromBytes(logID)
	if err != nil {
		t.Fatalf("bad logID: %v", err)
	}

	logIDStr := logIDUUID.String()

	// Compute SHA256 content hash
	shasher := sha256.New()
	_, err = shasher.Write(content)
	require.NoError(t, err)
	contentHash := shasher.Sum(nil)
	contentHashStr := fmt.Sprintf("%x", contentHash)

	// Compute MD5 ETag
	masher := md5.New()
	_, err = masher.Write(content)
	require.NoError(t, err)
	etag := masher.Sum(nil)
	etagStr := fmt.Sprintf("%x", etag)

	notification := consumer.R2Notification{
		Account:   "account",
		Action:    "PutObject",
		Bucket:    "canopy-dev-1-leaves",
		EventTime: g.SinceLastJitter().UTC().Truncate(time.Millisecond).Format(time.RFC3339),
		Object: consumer.R2Object{
			Key:  fmt.Sprintf("logs/%s/leaves/%d/%s", logIDStr, fenceIndex, contentHashStr),
			Size: int64(len(content)),
			ETag: etagStr,
		},
	}

	body, err := json.Marshal(notification)
	if err != nil {
		t.Fatalf("marshal notification: %v", err)
	}

	bodyStringJSON, err := json.Marshal(string(body))
	if err != nil {
		t.Fatalf("wrap notification: %v", err)
	}

	raw := json.RawMessage(bodyStringJSON)

	msg := consumer.QueueMessage{
		ID:   "message-id",
		Body: raw,
	}
	return msg
}
