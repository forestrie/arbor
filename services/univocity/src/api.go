package univocity

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/forestrie/arbor/services/pkgs/publishproof"
)

// API provides the HTTP API for the univocity trust-root service.
type API struct {
	Logger *slog.Logger
	Pool   ChainResolver

	// Forests is the optional bounded resolution cache (positive entries are
	// verified mappings; negative entries bound repeated unknown lookups).
	// Resolution itself is pure point lookup — see resolve.go (plan-2607-10).
	Forests *ForestCache

	// Store is the univocity-owned genesis + grant + index store. When nil the
	// write/authorize endpoints are unavailable.
	Store Store
	// APIToken authenticates canopy->univocity write/authorize calls. When empty
	// those endpoints return 503 (disabled).
	APIToken string
	// AdminToken authenticates destructive admin endpoints (delete). When empty
	// the admin endpoints are disabled.
	AdminToken string
	// Bootstrap caches per-(chainId,contract) on-chain bootstrap keys.
	Bootstrap *bootstrapCache

	// ReservationTTL is how long a claim made by prepare lasts unless its
	// grant is committed (UNIVOCITY_RESERVATION_TTL); zero means
	// DefaultReservationTTL.
	ReservationTTL time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	// Authorities caches final and anchored authority answers.
	Authorities *AuthorityCache
	// Massifs reads owner logs' massifs for the create-grant leaf scan.
	Massifs MassifReaders
	// Leaves remembers leaf-scan progress per owner log and grant.
	Leaves *publishproof.GrantLeafIndex
}

// DefaultReservationTTL is the lapse time of a reservation (devdocs
// ADR-0075 decision 2).
const DefaultReservationTTL = 7 * 24 * time.Hour

func (a API) reservationTTL() time.Duration {
	if a.ReservationTTL > 0 {
		return a.ReservationTTL
	}
	return DefaultReservationTTL
}

func (a API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// RegisterRoutes wires scoped and logId-only endpoints onto the mux.
func (a API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/{chainId}/{contract}/root", a.handleScopedRoot)
	mux.HandleFunc("GET /api/{chainId}/{contract}/logs", a.handleScopedLogsList)
	mux.HandleFunc(
		"GET /api/{chainId}/{contract}/logs/{logId}/config",
		a.handleScopedLogConfig,
	)
	mux.HandleFunc(
		"GET /api/{chainId}/{contract}/logs/{logId}/public-root",
		a.handleScopedPublicRoot,
	)

	mux.HandleFunc("GET /api/logs/{logId}/root", a.handleLogIDRoot)
	mux.HandleFunc("GET /api/logs/{logId}/public-root", a.handleLogIDPublicRoot)
	// Authority for a claimed log: its state (reserved, committed,
	// sequenced, anchored or conflicted), root key, first unanchored
	// ancestor and whether the answer is final. Non-mutating GET; operators
	// only (canopy-api, the sealer, the publisher).
	mux.HandleFunc("GET /api/logs/{logId}/authority", a.handleLogIDAuthority)

	// Owned store: genesis + grants (token-auth).
	mux.HandleFunc("POST /api/forest/{logId}/genesis", a.handlePostGenesis)
	mux.HandleFunc("GET /api/forest/{logId}/genesis", a.handleGetGenesis)
	mux.HandleFunc("POST /api/grants", a.handlePostGrant)

	// Admin (admin-token): explicit, no automatic GC.
	mux.HandleFunc("DELETE /api/forest/{logId}/grants/{subject}", a.handleDeleteGrant)
	mux.HandleFunc("DELETE /api/forest/{logId}", a.handleDeleteForest)
}
