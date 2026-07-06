package publisher

import "testing"

func TestParseCheckpointKey(t *testing.T) {
	const uuid = "70717273-7475-4677-a879-7a7b7c7d7e7f"
	valid := "v2/merklelog/checkpoints/14/" + uuid + "/0000000000000003.sth"

	ck, err := ParseCheckpointKey(valid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ck.MassifHeight != 14 {
		t.Errorf("massif height = %d, want 14", ck.MassifHeight)
	}
	if ck.MassifIndex != 3 {
		t.Errorf("massif index = %d, want 3", ck.MassifIndex)
	}
	if ck.LogID.String() != uuid {
		t.Errorf("logID = %s, want %s", ck.LogID.String(), uuid)
	}

	bad := []struct{ name, key string }{
		{"wrong prefix", "v2/merklelog/massifs/14/" + uuid + "/0000000000000003.sth"},
		{"too few segments", "v2/merklelog/checkpoints/14/" + uuid},
		{"zero height", "v2/merklelog/checkpoints/0/" + uuid + "/0000000000000003.sth"},
		{"bad uuid", "v2/merklelog/checkpoints/14/not-a-uuid/0000000000000003.sth"},
		{"not sth", "v2/merklelog/checkpoints/14/" + uuid + "/0000000000000003.log"},
		{"bad index", "v2/merklelog/checkpoints/14/" + uuid + "/abc.sth"},
	}
	for _, tc := range bad {
		if _, err := ParseCheckpointKey(tc.key); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}
