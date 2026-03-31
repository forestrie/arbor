package scout

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	cborcodec "github.com/datatrails/go-datatrails-common/cbor"
)

func TestHandleFindAppID_Success(t *testing.T) {
	logger, _ := NewLogger(0)

	api, err := NewAPI(logger)
	if err != nil {
		t.Fatalf("NewAPI failed: %v", err)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	const (
		logID = "746573742d6c6f67"                                                 // "test-log" encoded as hex
		appID = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" // 32 bytes hex
	)

	// Test successful request with all parameters
	url := ts.URL + "/api/logs/" + logID + "/find-appid/" + appID + "?massif-range=5&mmr-index=100"
	req, err := http.NewRequest(http.MethodGet, url, nil)
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

	// Check cache headers
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "public, max-age=31536000, immutable" {
		t.Errorf("expected cache-control header, got %q", cacheControl)
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

	var out FindAppIDResponse
	if err := codec.UnmarshalInto(body, &out); err != nil {
		t.Fatalf("UnmarshalInto failed: %v", err)
	}

	expectedLogIDBytes, _ := decodeLogID(logID)
	if !bytesEqual(out.LogID, expectedLogIDBytes) {
		t.Errorf("expected logId %x, got %x", expectedLogIDBytes, out.LogID)
	}

	expectedAppIDBytes, _ := decodeAndValidateAppID(appID)
	if !bytesEqual(out.AppID, expectedAppIDBytes) {
		t.Errorf("expected appId %x, got %x", expectedAppIDBytes, out.AppID)
	}

	if out.Found {
		t.Error("expected found to be false in stub implementation")
	}

	if out.MassifIndex != 0 {
		t.Errorf("expected massifIndex 0 (computed from mmr-index 100), got %d", out.MassifIndex)
	}
}

func TestHandleFindAppID_InvalidMethod(t *testing.T) {
	logger, _ := NewLogger(0)

	api, err := NewAPI(logger)
	if err != nil {
		t.Fatalf("NewAPI failed: %v", err)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	const (
		logID = "746573742d6c6f67" // "test-log" encoded as hex
		appID = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	)

	url := ts.URL + "/api/logs/" + logID + "/find-appid/" + appID + "?massif-range=1"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", resp.StatusCode)
	}
}

func TestHandleFindAppID_InvalidAppID(t *testing.T) {
	logger, _ := NewLogger(0)

	api, err := NewAPI(logger)
	if err != nil {
		t.Fatalf("NewAPI failed: %v", err)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	testCases := []struct {
		name  string
		appID string
	}{
		{"too short", "1234567890abcdef"},
		{"too long", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00"},
		{"invalid hex", "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := ts.URL + "/api/logs/746573742d6c6f67/find-appid/" + tc.appID + "?massif-range=1"
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected status 400, got %d", resp.StatusCode)
			}
		})
	}
}

func TestHandleFindAppID_MissingMassifRange(t *testing.T) {
	logger, _ := NewLogger(0)

	api, err := NewAPI(logger)
	if err != nil {
		t.Fatalf("NewAPI failed: %v", err)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	const (
		logID = "746573742d6c6f67" // "test-log" encoded as hex
		appID = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	)

	url := ts.URL + "/api/logs/" + logID + "/find-appid/" + appID
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
}

func TestHandleFindAppID_InvalidPath(t *testing.T) {
	logger, _ := NewLogger(0)

	api, err := NewAPI(logger)
	if err != nil {
		t.Fatalf("NewAPI failed: %v", err)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	testCases := []string{
		"/api/logs/746573742d6c6f67/find-appid/",                 // missing appID
		"/api/logs//find-appid/1234567890abcdef",                 // missing logID
		"/api/logs/746573742d6c6f67/find-wrong/1234567890abcdef", // wrong operation
	}

	for _, path := range testCases {
		t.Run(path, func(t *testing.T) {
			url := ts.URL + path + "?massif-range=1"
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected status 404, got %d", resp.StatusCode)
			}
		})
	}
}
