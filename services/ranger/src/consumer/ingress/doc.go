// Package ingress provides types and functions for consuming entries from the
// forestrie-ingress Durable Object queue.
//
// The DO queue replaces the Cloudflare Queue-based ingress path, providing
// domain-aware batching by logId and limit-based acknowledgement.
//
// See: arbor/docs/arc-cloudflare-do-ingress.md
package ingress
