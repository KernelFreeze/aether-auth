package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestServiceErrorMatchesByKind(t *testing.T) {
	cause := errors.New("hash mismatch")
	err := NewServiceError(ErrorKindInvalidCredentials, "password verification failed", cause)
	wrapped := errors.Join(errors.New("login failed"), err)

	if !errors.Is(wrapped, ErrInvalidCredentials) {
		t.Fatalf("errors.Is() = false, want true")
	}
	if errors.Is(wrapped, ErrLockedAccount) {
		t.Fatalf("errors.Is() matched locked account")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is() did not match cause")
	}

	kind, ok := ErrorKindOf(wrapped)
	if !ok {
		t.Fatal("ErrorKindOf() ok = false, want true")
	}
	if kind != ErrorKindInvalidCredentials {
		t.Fatalf("ErrorKindOf() = %q, want %q", kind, ErrorKindInvalidCredentials)
	}
}

func TestDefaultErrorIDFallsBackToInternal(t *testing.T) {
	if got := DefaultErrorID(ErrorKindExpiredChallenge); got != ErrorIDExpiredChallenge {
		t.Fatalf("DefaultErrorID() = %q, want %q", got, ErrorIDExpiredChallenge)
	}
	if got := DefaultErrorID("new_kind"); got != ErrorIDInternal {
		t.Fatalf("DefaultErrorID() = %q, want %q", got, ErrorIDInternal)
	}
}

func TestLoginPublicErrorDoesNotLeakAccountState(t *testing.T) {
	invalid := PublicErrorFor(ErrInvalidCredentials, PublicErrorContextLogin)
	locked := PublicErrorFor(ErrLockedAccount, PublicErrorContextLogin)

	if !reflect.DeepEqual(invalid, locked) {
		t.Fatalf("login errors differ:\ninvalid = %#v\nlocked  = %#v", invalid, locked)
	}
	if invalid.Status != http.StatusUnauthorized {
		t.Fatalf("login status = %d, want %d", invalid.Status, http.StatusUnauthorized)
	}
	if invalid.Code != "invalid_credentials" {
		t.Fatalf("login code = %q, want invalid_credentials", invalid.Code)
	}
	if invalid.ErrorID != ErrorIDLoginGeneric {
		t.Fatalf("login error ID = %q, want %q", invalid.ErrorID, ErrorIDLoginGeneric)
	}
}

func TestPasswordResetPublicErrorUsesGenericAcceptedResponse(t *testing.T) {
	invalid := PublicErrorFor(ErrInvalidCredentials, PublicErrorContextPasswordReset)
	malformed := PublicErrorFor(ErrMalformedInput, PublicErrorContextPasswordReset)

	if !reflect.DeepEqual(invalid, malformed) {
		t.Fatalf("reset errors differ:\ninvalid   = %#v\nmalformed = %#v", invalid, malformed)
	}
	if invalid.Status != http.StatusAccepted {
		t.Fatalf("reset status = %d, want %d", invalid.Status, http.StatusAccepted)
	}
	if invalid.Code != "reset_request_accepted" {
		t.Fatalf("reset code = %q, want reset_request_accepted", invalid.Code)
	}
}

func TestDefaultPublicErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "expired challenge", err: ErrExpiredChallenge, wantStatus: http.StatusBadRequest, wantCode: "expired_challenge"},
		{name: "replayed challenge", err: ErrReplayedChallenge, wantStatus: http.StatusBadRequest, wantCode: "replayed_challenge"},
		{name: "provider failure", err: ErrProviderFailure, wantStatus: http.StatusBadGateway, wantCode: "provider_failure"},
		{name: "insufficient scope", err: ErrInsufficientScope, wantStatus: http.StatusForbidden, wantCode: "insufficient_scope"},
		{name: "policy denied", err: ErrPolicyDenied, wantStatus: http.StatusForbidden, wantCode: "policy_denied"},
		{name: "unknown", err: errors.New("boom"), wantStatus: http.StatusInternalServerError, wantCode: "internal_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PublicErrorFor(tt.err, PublicErrorContextDefault)
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tt.wantStatus)
			}
			if got.Code != tt.wantCode {
				t.Fatalf("code = %q, want %q", got.Code, tt.wantCode)
			}
			if got.Type == "" || got.Title == "" || got.Detail == "" || got.ErrorID == "" {
				t.Fatalf("public error has empty fields: %#v", got)
			}
		})
	}
}
