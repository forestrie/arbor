module github.com/forestrie/arbor/services/sealer

go 1.24.0

toolchain go1.24.4

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/ethereum/go-ethereum v1.17.1
	github.com/forestrie/arbor/services/pkgs/delegatekeys v0.0.0
	github.com/forestrie/arbor/services/pkgs/delegationcert v0.0.0
	github.com/forestrie/arbor/services/pkgs/logid v0.0.0
	github.com/forestrie/arbor/services/pkgs/logredact v0.0.0
	github.com/fxamacker/cbor/v2 v2.9.0
	github.com/google/uuid v1.6.0
	github.com/veraison/go-cose v1.3.0
	golang.org/x/crypto v0.45.0
	google.golang.org/api v0.257.0
)

replace github.com/forestrie/arbor/services/pkgs/delegatekeys => ../../pkgs/delegatekeys

replace github.com/forestrie/arbor/services/pkgs/delegationcert => ../../pkgs/delegationcert

replace github.com/forestrie/arbor/services/pkgs/logid => ../../pkgs/logid

replace github.com/forestrie/arbor/services/pkgs/logredact => ../../pkgs/logredact

require (
	cloud.google.com/go/auth v0.17.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/consensys/gnark-crypto v0.18.1 // indirect
	github.com/crate-crypto/go-eth-kzg v1.4.0 // indirect
	github.com/ethereum/c-kzg-4844/v2 v2.1.6 // indirect
	github.com/ethereum/go-ethereum v1.17.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.7 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/metric v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/oauth2 v0.33.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251222181119-0a764e51fe1b // indirect
	google.golang.org/grpc v1.77.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
