module github.com/forestrie/arbor/services/scout

go 1.24.0

toolchain go1.24.4

require (
	github.com/datatrails/go-datatrails-common v0.30.0
	github.com/forestrie/arbor/services/pkgs/logredact v0.0.0
)

replace github.com/forestrie/arbor/services/pkgs/logredact => ../../pkgs/logredact

require (
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)
