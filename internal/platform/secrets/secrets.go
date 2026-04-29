// Package secrets resolves secret values referenced from config by URI. Only
// the "env://" scheme is wired up at scaffold time; future backends (vault,
// aws-sm, gcp-sm, file) implement Provider and register themselves with
// NewMux.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ErrNotFound is returned when a referenced secret cannot be resolved.
var ErrNotFound = errors.New("secret not found")

// Provider resolves a secret URI to its raw byte value. Implementations must
// be safe for concurrent use.
type Provider interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// EnvProvider resolves env://VARNAME references via os.Getenv.
type EnvProvider struct{}

// Resolve looks up the named environment variable. The empty string is
// treated as "not found" to avoid silently using a blank secret.
func (EnvProvider) Resolve(_ context.Context, ref string) ([]byte, error) {
	name, err := envName(ref)
	if err != nil {
		return nil, err
	}
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return nil, fmt.Errorf("%w: env://%s", ErrNotFound, name)
	}
	return []byte(v), nil
}

func envName(ref string) (string, error) {
	if !strings.HasPrefix(ref, "env://") {
		return "", fmt.Errorf("EnvProvider: unsupported scheme %q", ref)
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("EnvProvider: parse %q: %w", ref, err)
	}
	name := u.Host
	if name == "" {
		name = strings.TrimPrefix(u.Path, "/")
	}
	if name == "" {
		return "", fmt.Errorf("EnvProvider: empty variable name in %q", ref)
	}
	return name, nil
}

// Mux dispatches a secret reference to the matching backend by URI scheme.
type Mux struct {
	backends map[string]Provider
}

// NewMux returns a Mux pre-registered with the env:// backend.
func NewMux() *Mux {
	return &Mux{backends: map[string]Provider{
		"env": EnvProvider{},
	}}
}

// Register adds a backend for the given URI scheme (e.g. "vault", "awssm").
func (m *Mux) Register(scheme string, p Provider) {
	m.backends[scheme] = p
}

// Resolve dispatches to the backend matching the URI scheme.
func (m *Mux) Resolve(ctx context.Context, ref string) ([]byte, error) {
	scheme, _, ok := strings.Cut(ref, "://")
	if !ok {
		return nil, fmt.Errorf("secrets: %q is not a URI reference", ref)
	}
	b, ok := m.backends[scheme]
	if !ok {
		return nil, fmt.Errorf("secrets: no backend for scheme %q", scheme)
	}
	return b.Resolve(ctx, ref)
}
