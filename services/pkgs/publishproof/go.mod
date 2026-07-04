module github.com/forestrie/arbor/services/pkgs/publishproof

go 1.24.4

require (
	github.com/ethereum/go-ethereum v1.17.1
	github.com/forestrie/go-univocity v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/forestrie/arbor/services/pkgs/s3storage => ../s3storage
	github.com/forestrie/go-merklelog/bloom => ../../_deps/go-merklelog/bloom
	github.com/forestrie/go-merklelog/massifs => ../../_deps/go-merklelog/massifs
	github.com/forestrie/go-merklelog/mmr => ../../_deps/go-merklelog/mmr
	github.com/forestrie/go-merklelog/urkle => ../../_deps/go-merklelog/urkle
	github.com/forestrie/go-sigv4 => ../../_deps/go-sigv4
	github.com/forestrie/go-univocity => ../../_deps/go-univocity
)
