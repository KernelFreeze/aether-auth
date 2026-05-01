package auth

import (
	"context"
	"fmt"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

// Orchestrator routes auth method setup and verification by credential kind.
// It is the Stage 1 skeleton; policy checks, rate limiting, auditing, timing
// equalization, and session issuance belong in later auth services.
type Orchestrator struct {
	methods map[account.CredentialKind]AuthMethod
}

// NewOrchestrator builds an orchestrator and registers the supplied methods.
func NewOrchestrator(methods ...AuthMethod) (*Orchestrator, error) {
	o := &Orchestrator{methods: make(map[account.CredentialKind]AuthMethod, len(methods))}
	for _, method := range methods {
		if err := o.RegisterMethod(method); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// RegisterMethod adds one auth method for its credential kind.
func (o *Orchestrator) RegisterMethod(method AuthMethod) error {
	if method == nil {
		return NewServiceError(ErrorKindMalformedInput, "auth method is nil", nil)
	}
	if o.methods == nil {
		o.methods = make(map[account.CredentialKind]AuthMethod)
	}

	kind := method.Kind()
	if !kind.Valid() {
		return NewServiceError(ErrorKindMalformedInput, fmt.Sprintf("auth method has invalid kind %q", kind), nil)
	}
	if _, exists := o.methods[kind]; exists {
		return NewServiceError(ErrorKindMalformedInput, fmt.Sprintf("auth method already registered for %q", kind), nil)
	}

	o.methods[kind] = method
	return nil
}

// Method returns the registered auth method for kind.
func (o *Orchestrator) Method(kind account.CredentialKind) (AuthMethod, bool) {
	if o == nil || o.methods == nil {
		return nil, false
	}
	method, ok := o.methods[kind]
	return method, ok
}

// Begin starts the method-specific setup for kind.
func (o *Orchestrator) Begin(ctx context.Context, kind account.CredentialKind, req BeginRequest) (BeginResult, error) {
	method, err := o.method(kind)
	if err != nil {
		return BeginResult{}, err
	}
	return method.Begin(ctx, req)
}

// Verify verifies credentials or challenge responses for kind.
func (o *Orchestrator) Verify(ctx context.Context, kind account.CredentialKind, req VerifyRequest) (AuthResult, error) {
	method, err := o.method(kind)
	if err != nil {
		return AuthResult{}, err
	}
	return method.Verify(ctx, req)
}

func (o *Orchestrator) method(kind account.CredentialKind) (AuthMethod, error) {
	method, ok := o.Method(kind)
	if !ok {
		return nil, NewServiceError(ErrorKindMalformedInput, fmt.Sprintf("auth method not registered for %q", kind), nil)
	}
	return method, nil
}
