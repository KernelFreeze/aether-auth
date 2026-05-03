package mfa

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/auth/totp"
	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestMFAModuleVerifyTOTPUpgradesPartialSession(t *testing.T) {
	accountID := mustMFAAccountID(t, "018f1f74-10a1-7000-9000-000000003001")
	partialID := mustMFASessionID(t, "018f1f74-10a1-7000-9000-000000003002")
	fullID := mustMFASessionID(t, "018f1f74-10a1-7000-9000-000000003003")
	now := time.Now().UTC()
	issuer := &mfaSessionIssuer{
		result: auth.SessionIssueResult{
			SessionID:    fullID,
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresAt:    now.Add(15 * time.Minute),
		},
	}
	factors := &mfaTOTPVerifier{
		totpCheck: auth.FactorCheck{
			Kind:       account.FactorKindTOTP,
			VerifiedAt: now,
		},
	}
	router := mfaTestRouter(t, New(Deps{
		Policy: NewPolicyService(PolicyDeps{
			Sessions: issuer,
		}),
		PartialSessions: mfaPartialVerifier{
			partial: auth.PartialSession{
				ID:              partialID,
				AccountID:       accountID,
				VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword},
				ExpiresAt:       now.Add(time.Minute),
			},
		},
		Accounts: mfaAccountState{state: auth.AccountState{AccountID: accountID, MFARequired: true}},
		TOTP:     factors,
	}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/auth/mfa/verify", map[string]any{
		"partial_session_id": partialID.String(),
		"partial_token":      "partial-token",
		"kind":               "totp",
		"code":               "123456",
	}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body verifyResponse
	testutil.DecodeJSON(t, rec.Body, &body)
	if body.Status != "authenticated" || body.Session.ID != fullID.String() || body.Session.AccessToken != "access-token" || body.Session.RefreshToken != "refresh-token" {
		t.Fatalf("verify response = %#v", body)
	}
	if factors.totpReq.AccountID != accountID || factors.totpReq.Code != "123456" {
		t.Fatalf("totp request = %#v", factors.totpReq)
	}
	if got, want := issuer.req.VerifiedFactors, []account.FactorKind{account.FactorKindUser, account.FactorKindPassword, account.FactorKindTOTP}; len(got) != len(want) || got[2] != want[2] {
		t.Fatalf("issued factors = %#v, want %#v", got, want)
	}
	if strings.Contains(rec.Body.String(), "123456") || strings.Contains(rec.Body.String(), "partial-token") {
		t.Fatalf("mfa response leaked verifier material: %s", rec.Body.String())
	}
}

func TestMFAModuleVerifyRecoveryCodeUsesGenericFailure(t *testing.T) {
	accountID := mustMFAAccountID(t, "018f1f74-10a1-7000-9000-000000003004")
	partialID := mustMFASessionID(t, "018f1f74-10a1-7000-9000-000000003005")
	router := mfaTestRouter(t, New(Deps{
		Policy: NewPolicyService(PolicyDeps{Sessions: &mfaSessionIssuer{}}),
		PartialSessions: mfaPartialVerifier{
			partial: auth.PartialSession{
				ID:              partialID,
				AccountID:       accountID,
				VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword},
				ExpiresAt:       time.Now().Add(time.Minute),
			},
		},
		Accounts: mfaAccountState{state: auth.AccountState{AccountID: accountID, MFARequired: true}},
		TOTP:     &mfaTOTPVerifier{recoveryErr: auth.ErrInvalidCredentials},
	}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/auth/mfa/verify", map[string]any{
		"partial_session_id": partialID.String(),
		"partial_token":      "partial-token",
		"kind":               "recovery_code",
		"code":               "ABCD-EFGH",
	}))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	var body map[string]any
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["code"] != "invalid_mfa" {
		t.Fatalf("problem body = %#v", body)
	}
	for _, forbidden := range []string{"ABCD", "recovery", "partial-token"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("mfa error leaked %q: %s", forbidden, rec.Body.String())
		}
	}
}

func mfaTestRouter(t testing.TB, module *Module) *gin.Engine {
	t.Helper()
	testutil.SetGinTestMode(t)

	router := gin.New()
	module.RegisterRoutes(router.Group("/auth/mfa"), httpapi.Middlewares{})
	return router
}

type mfaPartialVerifier struct {
	partial auth.PartialSession
	err     error
}

func (v mfaPartialVerifier) VerifyPartialSession(context.Context, auth.PartialSessionVerifyRequest) (auth.PartialSession, error) {
	if v.err != nil {
		return auth.PartialSession{}, v.err
	}
	return v.partial, nil
}

type mfaAccountState struct {
	state auth.AccountState
	err   error
}

func (s mfaAccountState) AccountState(context.Context, account.AccountID) (auth.AccountState, error) {
	if s.err != nil {
		return auth.AccountState{}, s.err
	}
	return s.state, nil
}

type mfaTOTPVerifier struct {
	totpReq     totp.VerifyTOTPRequest
	recoveryReq totp.VerifyRecoveryCodeRequest
	totpCheck   auth.FactorCheck
	recoveryErr error
}

func (v *mfaTOTPVerifier) VerifyTOTP(_ context.Context, req totp.VerifyTOTPRequest) (auth.FactorCheck, auth.CredentialSnapshot, error) {
	v.totpReq = req
	if v.totpCheck.Kind == "" {
		v.totpCheck = auth.FactorCheck{Kind: account.FactorKindTOTP, VerifiedAt: time.Now()}
	}
	return v.totpCheck, auth.CredentialSnapshot{ID: req.CredentialID, AccountID: req.AccountID, Kind: account.CredentialKindTOTP, Verified: true}, nil
}

func (v *mfaTOTPVerifier) VerifyRecoveryCode(_ context.Context, req totp.VerifyRecoveryCodeRequest) (auth.FactorCheck, auth.CredentialSnapshot, error) {
	v.recoveryReq = req
	if v.recoveryErr != nil {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, v.recoveryErr
	}
	return auth.FactorCheck{Kind: account.FactorKindRecoveryCode, VerifiedAt: time.Now()}, auth.CredentialSnapshot{ID: req.CredentialID, AccountID: req.AccountID, Kind: account.CredentialKindRecoveryCode, Verified: true}, nil
}

type mfaSessionIssuer struct {
	req    auth.SessionIssueRequest
	result auth.SessionIssueResult
	err    error
}

func (i *mfaSessionIssuer) IssueSession(_ context.Context, req auth.SessionIssueRequest) (auth.SessionIssueResult, error) {
	i.req = req
	if i.err != nil {
		return auth.SessionIssueResult{}, i.err
	}
	return i.result, nil
}

func mustMFAAccountID(t testing.TB, value string) account.AccountID {
	t.Helper()
	id, err := account.ParseAccountID(value)
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	return id
}

func mustMFASessionID(t testing.TB, value string) account.SessionID {
	t.Helper()
	id, err := account.ParseSessionID(value)
	if err != nil {
		t.Fatalf("parse session id: %v", err)
	}
	return id
}
