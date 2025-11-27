package scout

import (
	"log/slog"
	"net/http"
	"strings"

	cborcodec "github.com/datatrails/go-datatrails-common/cbor"
)

const (
	cborContentType = "application/cbor"
)

// API provides the CBOR HTTP API surface for scout.
type API struct {
	Logger *slog.Logger
	CBOR   cborcodec.CBORCodec
}

func NewAPI(logger *slog.Logger) (API, error) {
	encOpts := cborcodec.NewDeterministicEncOpts()
	decOpts := cborcodec.NewDeterministicDecOpts()
	codec, err := cborcodec.NewCBORCodec(encOpts, decOpts)
	if err != nil {
		return API{}, err
	}
	return API{Logger: logger, CBOR: codec}, nil
}

// RegisterRoutes wires the scout API endpoints onto the provided mux.
//
// The following endpoints are served:
//
//	/api/logs/{logId}/head-index
//	/api/logs/{logId}/find-appid/{appId}
//	/api/logs/{logId}/find-extrabytes/{extraBytes}
func (a API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/logs/", a.routeHandler)
}

// routeHandler routes requests to the appropriate handler based on the URL path.
func (a API) routeHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Route to specific handlers based on path pattern
	if strings.Contains(path, "/head-index") {
		a.handleHeadIndex(w, r)
		return
	}

	if strings.Contains(path, "/find-appid/") {
		a.handleFindAppID(w, r)
		return
	}

	if strings.Contains(path, "/find-extrabytes/") {
		a.handleFindExtraBytes(w, r)
		return
	}

	// No matching route found
	a.writeProblem(w, r, http.StatusNotFound, "about:blank", "not found", "")
}
