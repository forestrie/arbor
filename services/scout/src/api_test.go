package scout

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	cborcodec "github.com/datatrails/go-datatrails-common/cbor"
)

func TestHeadIndex_UsesPathLogIDAndReturnsZeroIndex(t *testing.T) {
	logger, _ := NewLogger(0)

	api, err := NewAPI(logger)
	if err != nil {
		t.Fatalf("NewAPI failed: %v", err)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	const logID = "test-log"

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/logs/"+logID+"/head-index", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d, body=%s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	encOpts := cborcodec.NewDeterministicEncOpts()
	decOpts := cborcodec.NewDeterministicDecOpts()
	codec, err := cborcodec.NewCBORCodec(encOpts, decOpts)
	if err != nil {
		t.Fatalf("NewCBORCodec failed: %v", err)
	}

	var out struct {
		LogID    string `cbor:"logId"`
		MMRIndex uint64 `cbor:"mmrIndex"`
	}

	if err := codec.UnmarshalInto(body, &out); err != nil {
		t.Fatalf("UnmarshalInto failed: %v", err)
	}

	if out.LogID != logID {
		t.Fatalf("expected logId %q, got %q", logID, out.LogID)
	}

	if out.MMRIndex != 0 {
		t.Fatalf("expected mmrIndex 0, got %d", out.MMRIndex)
	}
}
