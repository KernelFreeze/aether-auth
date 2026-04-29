// Package ratelimit exposes Redis-backed sliding-window / GCRA limiters keyed
// by IP, account, and endpoint, plus a Gin middleware that enforces them
// before credential verification runs.
package ratelimit
