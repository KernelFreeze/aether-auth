// Package ratelimit exposes Redis-backed GCRA limiters keyed by IP, account,
// username, and endpoint. It also provides Gin middleware that feature modules
// can run before credential verification starts.
package ratelimit
