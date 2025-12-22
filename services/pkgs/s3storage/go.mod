module github.com/forestrie/arbor/services/pkgs/s3storage

go 1.24.0

toolchain go1.24.4

require (
	github.com/forestrie/go-merklelog/bloom v0.0.0-00010101000000-000000000000
	github.com/forestrie/go-merklelog/massifs v0.0.3
	github.com/forestrie/go-merklelog/urkle v0.0.0-00010101000000-000000000000
	github.com/forestrie/go-sigv4 v0.0.0-00010101000000-000000000000
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/forestrie/go-merklelog/mmr v0.0.2 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/ldclabs/cose/go v0.0.0-20221214142927-d22c1cfc2154 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/veraison/go-cose v1.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/forestrie/go-merklelog/bloom => ../../_deps/go-merklelog/bloom
	github.com/forestrie/go-merklelog/massifs => ../../_deps/go-merklelog/massifs
	github.com/forestrie/go-merklelog/mmr => ../../_deps/go-merklelog/mmr
	github.com/forestrie/go-merklelog/urkle => ../../_deps/go-merklelog/urkle
	github.com/forestrie/go-sigv4 => ../../_deps/go-sigv4
)
