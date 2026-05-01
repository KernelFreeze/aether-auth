package auth

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrorKind is the stable internal class for auth service failures. Handlers
// map these kinds to public responses instead of returning raw service errors.
type ErrorKind string

const (
	// ErrorKindInvalidCredentials means the credential proof did not match.
	ErrorKindInvalidCredentials ErrorKind = "invalid_credentials"
	// ErrorKindLockedAccount means the account cannot be used until a lock ends.
	ErrorKindLockedAccount ErrorKind = "locked_account"
	// ErrorKindExpiredChallenge means a one-time challenge is past its expiry.
	ErrorKindExpiredChallenge ErrorKind = "expired_challenge"
	// ErrorKindReplayedChallenge means a one-time challenge was already used.
	ErrorKindReplayedChallenge ErrorKind = "replayed_challenge"
	// ErrorKindMalformedInput means the request shape or field value is invalid.
	ErrorKindMalformedInput ErrorKind = "malformed_input"
	// ErrorKindProviderFailure means an external identity provider failed.
	ErrorKindProviderFailure ErrorKind = "provider_failure"
	// ErrorKindInsufficientScope means the caller lacks the required scope.
	ErrorKindInsufficientScope ErrorKind = "insufficient_scope"
	// ErrorKindPolicyDenied means a local security policy rejected the action.
	ErrorKindPolicyDenied ErrorKind = "policy_denied"
	// ErrorKindInternal means the service could not classify the failure safely.
	ErrorKindInternal ErrorKind = "internal_error"
)

// ErrorID is the stable identifier logged with an auth error. The short AUTH
// codes keep room for a later Zitadel-style error catalog without changing the
// public contract.
type ErrorID string

const (
	ErrorIDInvalidCredentials ErrorID = "AUTH-0001"
	ErrorIDLockedAccount      ErrorID = "AUTH-0002"
	ErrorIDExpiredChallenge   ErrorID = "AUTH-0003"
	ErrorIDReplayedChallenge  ErrorID = "AUTH-0004"
	ErrorIDMalformedInput     ErrorID = "AUTH-0005"
	ErrorIDProviderFailure    ErrorID = "AUTH-0006"
	ErrorIDInsufficientScope  ErrorID = "AUTH-0007"
	ErrorIDPolicyDenied       ErrorID = "AUTH-0008"
	ErrorIDInternal           ErrorID = "AUTH-0009"
	ErrorIDLoginGeneric       ErrorID = "AUTH-LOGIN-0001"
	ErrorIDPasswordReset      ErrorID = "AUTH-RESET-0001"
)

// ServiceError is the error type returned by auth services and methods.
type ServiceError struct {
	Kind    ErrorKind
	ID      ErrorID
	Message string
	Err     error
}

var (
	ErrInvalidCredentials = &ServiceError{Kind: ErrorKindInvalidCredentials, ID: ErrorIDInvalidCredentials}
	ErrLockedAccount      = &ServiceError{Kind: ErrorKindLockedAccount, ID: ErrorIDLockedAccount}
	ErrExpiredChallenge   = &ServiceError{Kind: ErrorKindExpiredChallenge, ID: ErrorIDExpiredChallenge}
	ErrReplayedChallenge  = &ServiceError{Kind: ErrorKindReplayedChallenge, ID: ErrorIDReplayedChallenge}
	ErrMalformedInput     = &ServiceError{Kind: ErrorKindMalformedInput, ID: ErrorIDMalformedInput}
	ErrProviderFailure    = &ServiceError{Kind: ErrorKindProviderFailure, ID: ErrorIDProviderFailure}
	ErrInsufficientScope  = &ServiceError{Kind: ErrorKindInsufficientScope, ID: ErrorIDInsufficientScope}
	ErrPolicyDenied       = &ServiceError{Kind: ErrorKindPolicyDenied, ID: ErrorIDPolicyDenied}
	ErrInternal           = &ServiceError{Kind: ErrorKindInternal, ID: ErrorIDInternal}
)

// NewServiceError creates a classified service error. The message is for logs
// and tests; callers must use PublicErrorFor before writing an HTTP response.
func NewServiceError(kind ErrorKind, message string, err error) *ServiceError {
	return &ServiceError{
		Kind:    normalizeErrorKind(kind),
		ID:      DefaultErrorID(kind),
		Message: message,
		Err:     err,
	}
}

func (e *ServiceError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return string(e.Kind)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *ServiceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is lets errors.Is match service errors by kind.
func (e *ServiceError) Is(target error) bool {
	if e == nil {
		return false
	}
	t, ok := target.(*ServiceError)
	if !ok {
		return false
	}
	if t.Kind != "" && e.Kind != t.Kind {
		return false
	}
	if t.ID != "" && e.ID != t.ID {
		return false
	}
	return true
}

// ErrorKindOf returns the auth error kind inside err.
func ErrorKindOf(err error) (ErrorKind, bool) {
	var serviceErr *ServiceError
	if !errors.As(err, &serviceErr) {
		return "", false
	}
	return serviceErr.Kind, true
}

// DefaultErrorID returns the catalog ID for kind.
func DefaultErrorID(kind ErrorKind) ErrorID {
	switch normalizeErrorKind(kind) {
	case ErrorKindInvalidCredentials:
		return ErrorIDInvalidCredentials
	case ErrorKindLockedAccount:
		return ErrorIDLockedAccount
	case ErrorKindExpiredChallenge:
		return ErrorIDExpiredChallenge
	case ErrorKindReplayedChallenge:
		return ErrorIDReplayedChallenge
	case ErrorKindMalformedInput:
		return ErrorIDMalformedInput
	case ErrorKindProviderFailure:
		return ErrorIDProviderFailure
	case ErrorKindInsufficientScope:
		return ErrorIDInsufficientScope
	case ErrorKindPolicyDenied:
		return ErrorIDPolicyDenied
	default:
		return ErrorIDInternal
	}
}

// PublicErrorContext selects the public mapping for account-sensitive flows.
type PublicErrorContext string

const (
	PublicErrorContextDefault       PublicErrorContext = ""
	PublicErrorContextLogin         PublicErrorContext = "login"
	PublicErrorContextPasswordReset PublicErrorContext = "password_reset"
)

// PublicError is the sanitized error contract handlers may return to clients.
type PublicError struct {
	Status  int
	Type    string
	Code    string
	Title   string
	Detail  string
	ErrorID ErrorID
}

// PublicErrorFor maps internal service errors to safe client responses.
func PublicErrorFor(err error, ctx PublicErrorContext) PublicError {
	kind, ok := ErrorKindOf(err)
	if !ok {
		kind = ErrorKindInternal
	}
	kind = normalizeErrorKind(kind)

	switch ctx {
	case PublicErrorContextLogin:
		if kind == ErrorKindInvalidCredentials || kind == ErrorKindLockedAccount {
			return PublicError{
				Status:  http.StatusUnauthorized,
				Type:    "https://aether-auth.local/problems/invalid-credentials",
				Code:    "invalid_credentials",
				Title:   "Invalid credentials",
				Detail:  "The username or password is incorrect.",
				ErrorID: ErrorIDLoginGeneric,
			}
		}
	case PublicErrorContextPasswordReset:
		if kind == ErrorKindInvalidCredentials || kind == ErrorKindLockedAccount || kind == ErrorKindMalformedInput {
			return PublicError{
				Status:  http.StatusAccepted,
				Type:    "https://aether-auth.local/problems/reset-request-accepted",
				Code:    "reset_request_accepted",
				Title:   "Reset request accepted",
				Detail:  "If the account can be reset, instructions will be sent.",
				ErrorID: ErrorIDPasswordReset,
			}
		}
	}

	return defaultPublicError(kind)
}

func defaultPublicError(kind ErrorKind) PublicError {
	switch kind {
	case ErrorKindInvalidCredentials:
		return publicError(http.StatusUnauthorized, "invalid-credentials", "invalid_credentials", "Invalid credentials", "The credentials are invalid.", ErrorIDInvalidCredentials)
	case ErrorKindLockedAccount:
		return publicError(http.StatusLocked, "locked-account", "locked_account", "Account unavailable", "The account is temporarily unavailable.", ErrorIDLockedAccount)
	case ErrorKindExpiredChallenge:
		return publicError(http.StatusBadRequest, "expired-challenge", "expired_challenge", "Expired challenge", "The challenge has expired.", ErrorIDExpiredChallenge)
	case ErrorKindReplayedChallenge:
		return publicError(http.StatusBadRequest, "replayed-challenge", "replayed_challenge", "Replayed challenge", "The challenge has already been used.", ErrorIDReplayedChallenge)
	case ErrorKindMalformedInput:
		return publicError(http.StatusBadRequest, "malformed-input", "malformed_input", "Malformed input", "The request could not be processed.", ErrorIDMalformedInput)
	case ErrorKindProviderFailure:
		return publicError(http.StatusBadGateway, "provider-failure", "provider_failure", "Provider failure", "The identity provider could not complete the request.", ErrorIDProviderFailure)
	case ErrorKindInsufficientScope:
		return publicError(http.StatusForbidden, "insufficient-scope", "insufficient_scope", "Insufficient scope", "The caller does not have the required scope.", ErrorIDInsufficientScope)
	case ErrorKindPolicyDenied:
		return publicError(http.StatusForbidden, "policy-denied", "policy_denied", "Policy denied", "The request was denied by policy.", ErrorIDPolicyDenied)
	default:
		return publicError(http.StatusInternalServerError, "internal-error", "internal_error", "Internal error", "The request could not be completed.", ErrorIDInternal)
	}
}

func publicError(status int, problemType, code, title, detail string, id ErrorID) PublicError {
	return PublicError{
		Status:  status,
		Type:    "https://aether-auth.local/problems/" + problemType,
		Code:    code,
		Title:   title,
		Detail:  detail,
		ErrorID: id,
	}
}

func normalizeErrorKind(kind ErrorKind) ErrorKind {
	switch kind {
	case ErrorKindInvalidCredentials,
		ErrorKindLockedAccount,
		ErrorKindExpiredChallenge,
		ErrorKindReplayedChallenge,
		ErrorKindMalformedInput,
		ErrorKindProviderFailure,
		ErrorKindInsufficientScope,
		ErrorKindPolicyDenied,
		ErrorKindInternal:
		return kind
	default:
		return ErrorKindInternal
	}
}
