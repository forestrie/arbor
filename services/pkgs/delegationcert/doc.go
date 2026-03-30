// Package delegationcert holds shared types and parsers for Forestrie
// delegation COSE Sign1 certificates (application/forestrie.delegation+cbor).
//
// Arbor Go services import this module for module hygiene and to avoid drift.
// The Canopy delegation-signer Worker (TypeScript) is the reference issuer;
// its issuance logic is intentionally not refactored here—keep implementations
// aligned via tests and golden vectors when behavior changes.
package delegationcert
