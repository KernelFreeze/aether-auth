package account

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/authctx"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestAccountModuleProfileRoutes(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000501")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	profiles := &fakeProfileManager{
		profile: AccountProfile{
			ID:          accountID,
			Username:    "celeste",
			DisplayName: "Celeste",
			Metadata:    json.RawMessage(`{"timezone":"America/Bogota"}`),
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
	router := accountTestRouter(t, New(Deps{Profiles: profiles}), authenticatedAs(accountID, time.Time{}))

	getRec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodGet, "/account/profile", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", getRec.Code, http.StatusOK)
	}
	var getBody map[string]any
	testutil.DecodeJSON(t, getRec.Body, &getBody)
	if getBody["id"] != accountID.String() || getBody["display_name"] != "Celeste" {
		t.Fatalf("profile body = %#v", getBody)
	}

	patchRec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPatch, "/account/profile", map[string]any{
		"display_name": " Celeste Love ",
		"metadata": map[string]any{
			"locale": "en-US",
		},
	}))
	if patchRec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, want %d", patchRec.Code, http.StatusOK)
	}
	if !profiles.update.DisplayNameSet || profiles.update.DisplayName != " Celeste Love " || !profiles.update.MetadataSet {
		t.Fatalf("profile update request = %#v", profiles.update)
	}
}

func TestAccountModuleListsCredentialsWithoutSecrets(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000502")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000503")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	credentials := &fakeCredentialManager{
		credentials: []Credential{
			{
				ID:              credentialID,
				AccountID:       accountID,
				Kind:            CredentialKindOIDC,
				Provider:        "github",
				ExternalSubject: "sub-123",
				DisplayName:     "GitHub",
				Verified:        true,
				CreatedAt:       now,
				UpdatedAt:       now,
				LastUsedAt:      now,
				Payload: CredentialPayload{
					Ciphertext: []byte("secret-ciphertext"),
				},
			},
		},
	}
	router := accountTestRouter(t, New(Deps{Credentials: credentials}), authenticatedAs(accountID, time.Time{}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodGet, "/account/credentials", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"secret-ciphertext", "external_subject", "sub-123", "payload"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("credential response leaked %q: %s", forbidden, body)
		}
	}
	var decoded credentialsResponse
	testutil.DecodeJSON(t, strings.NewReader(body), &decoded)
	if len(decoded.Credentials) != 1 || decoded.Credentials[0].Provider != "github" {
		t.Fatalf("credentials response = %#v", decoded)
	}
}

func TestAccountModuleRemoveCredentialUsesReauthenticationContext(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000504")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000505")
	reauthenticatedAt := time.Date(2026, 5, 1, 11, 59, 0, 0, time.UTC)
	credentials := &fakeCredentialManager{}
	router := accountTestRouter(t, New(Deps{Credentials: credentials}), authenticatedAs(accountID, reauthenticatedAt))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodDelete, "/account/credentials/"+credentialID.String(), nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if credentials.remove.AccountID != accountID || credentials.remove.CredentialID != credentialID || !credentials.remove.ReauthenticatedAt.Equal(reauthenticatedAt) {
		t.Fatalf("remove request = %#v", credentials.remove)
	}
}

func TestAccountModuleRemoveCredentialProtectsLastCredential(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000506")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000507")
	credentials := &fakeCredentialManager{removeErr: ErrLastCredential}
	router := accountTestRouter(t, New(Deps{Credentials: credentials}), authenticatedAs(accountID, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodDelete, "/account/credentials/"+credentialID.String(), nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	var body map[string]any
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["code"] != "last_credential" {
		t.Fatalf("problem body = %#v", body)
	}
}

func TestAccountModuleListsSessionsWithoutTokenMaterial(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000508")
	currentID := mustCredentialSessionID(t, "018f1f74-10a1-7000-9000-000000000509")
	otherID := mustCredentialSessionID(t, "018f1f74-10a1-7000-9000-000000000510")
	now := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	sessions := &fakeSessionManager{
		sessions: []AccountSession{
			{
				ID:        currentID,
				AccountID: accountID,
				IP:        "203.0.113.10",
				UserAgent: "Firefox on Fedora",
				CreatedAt: now.Add(-time.Hour),
				ExpiresAt: now.Add(90 * 24 * time.Hour),
			},
			{
				ID:        otherID,
				AccountID: accountID,
				IP:        "203.0.113.11",
				UserAgent: "Mobile",
				CreatedAt: now.Add(-2 * time.Hour),
				ExpiresAt: now.Add(30 * 24 * time.Hour),
			},
		},
	}
	router := accountTestRouter(t, New(Deps{Sessions: sessions}), authenticatedAsSession(accountID, currentID, time.Time{}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodGet, "/account/sessions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"access", "refresh", "token", "jti"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("session response leaked %q: %s", forbidden, body)
		}
	}
	var decoded accountSessionsResponse
	testutil.DecodeJSON(t, strings.NewReader(body), &decoded)
	if len(decoded.Sessions) != 2 || !decoded.Sessions[0].Current || decoded.Sessions[1].Current {
		t.Fatalf("sessions response = %#v", decoded)
	}
	if sessions.listAccountID != accountID {
		t.Fatalf("list account id = %s, want %s", sessions.listAccountID, accountID)
	}
}

func TestAccountModuleRevokesAuthenticatedAccountSession(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000511")
	currentID := mustCredentialSessionID(t, "018f1f74-10a1-7000-9000-000000000512")
	revokedID := mustCredentialSessionID(t, "018f1f74-10a1-7000-9000-000000000513")
	sessions := &fakeSessionManager{}
	router := accountTestRouter(t, New(Deps{Sessions: sessions}), authenticatedAsSession(accountID, currentID, time.Time{}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodDelete, "/account/sessions/"+revokedID.String(), nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if sessions.revokeAccountID != accountID || sessions.revokeSessionID != revokedID {
		t.Fatalf("revoke request = account %s session %s", sessions.revokeAccountID, sessions.revokeSessionID)
	}
}

func TestAccountModuleRevokesMissingSessionAsNotFound(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000514")
	sessionID := mustCredentialSessionID(t, "018f1f74-10a1-7000-9000-000000000515")
	sessions := &fakeSessionManager{revokeErr: ErrSessionNotFound}
	router := accountTestRouter(t, New(Deps{Sessions: sessions}), authenticatedAs(accountID, time.Time{}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodDelete, "/account/sessions/"+sessionID.String(), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	var body map[string]any
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["code"] != "session_not_found" {
		t.Fatalf("problem body = %#v", body)
	}
}

func TestAccountModuleTOTPRoutes(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000516")
	totpID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000517")
	recoveryID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000518")
	reauthenticatedAt := time.Date(2026, 5, 3, 13, 0, 0, 0, time.UTC)
	profiles := &fakeProfileManager{profile: AccountProfile{
		ID:       accountID,
		Username: "celeste",
	}}
	credentials := &fakeCredentialManager{
		credentials: []Credential{
			{ID: totpID, AccountID: accountID, Kind: CredentialKindTOTP, Verified: true},
			{ID: recoveryID, AccountID: accountID, Kind: CredentialKindRecoveryCode, Verified: true},
		},
	}
	totpManager := &fakeTOTPManager{
		enrollment: TOTPEnrollment{
			AccountID:       accountID,
			CredentialID:    totpID,
			Secret:          "JBSWY3DPEHPK3PXP",
			ProvisioningURI: "otpauth://totp/Aether%20Auth:celeste?secret=JBSWY3DPEHPK3PXP",
		},
		confirmed: TOTPCredential{
			ID:        totpID,
			AccountID: accountID,
			Kind:      CredentialKindTOTP,
			Verified:  true,
		},
		recovery: GeneratedRecoveryCodes{
			AccountID:    accountID,
			CredentialID: recoveryID,
			Codes:        []string{"ABCD1234EFGH", "JKLM5678NPQR"},
		},
	}
	router := accountTestRouter(t, New(Deps{
		Profiles:    profiles,
		Credentials: credentials,
		TOTP:        totpManager,
	}), authenticatedAs(accountID, reauthenticatedAt))

	enrollRec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/account/mfa/totp/enroll", map[string]any{
		"issuer": "Aether Auth",
	}))
	if enrollRec.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d, want %d: %s", enrollRec.Code, http.StatusCreated, enrollRec.Body.String())
	}
	if totpManager.enrollReq.AccountID != accountID || totpManager.enrollReq.AccountName != "celeste" || totpManager.enrollReq.Issuer != "Aether Auth" {
		t.Fatalf("enroll request = %#v", totpManager.enrollReq)
	}
	var enrollment totpEnrollmentResponse
	testutil.DecodeJSON(t, enrollRec.Body, &enrollment)
	if enrollment.CredentialID != totpID.String() || enrollment.Secret == "" || enrollment.ProvisioningURI == "" {
		t.Fatalf("enrollment response = %#v", enrollment)
	}

	confirmRec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/account/mfa/totp/confirm", map[string]any{
		"credential_id": totpID.String(),
		"code":          "123456",
	}))
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm status = %d, want %d: %s", confirmRec.Code, http.StatusOK, confirmRec.Body.String())
	}
	if totpManager.confirmReq.AccountID != accountID || totpManager.confirmReq.CredentialID != totpID || totpManager.confirmReq.Code != "123456" {
		t.Fatalf("confirm request = %#v", totpManager.confirmReq)
	}

	recoveryRec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/account/mfa/recovery-codes/regenerate", map[string]any{
		"credential_id": recoveryID.String(),
	}))
	if recoveryRec.Code != http.StatusOK {
		t.Fatalf("recovery status = %d, want %d: %s", recoveryRec.Code, http.StatusOK, recoveryRec.Body.String())
	}
	body := recoveryRec.Body.String()
	if strings.Contains(body, "hash") || strings.Contains(body, "payload") {
		t.Fatalf("recovery response leaked storage material: %s", body)
	}
	var recovery recoveryCodesResponse
	testutil.DecodeJSON(t, strings.NewReader(body), &recovery)
	if recovery.CredentialID != recoveryID.String() || len(recovery.Codes) != 2 {
		t.Fatalf("recovery response = %#v", recovery)
	}

	disableRec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodDelete, "/account/mfa/totp/"+totpID.String(), nil))
	if disableRec.Code != http.StatusNoContent {
		t.Fatalf("disable status = %d, want %d: %s", disableRec.Code, http.StatusNoContent, disableRec.Body.String())
	}
	if credentials.remove.AccountID != accountID || credentials.remove.CredentialID != totpID || !credentials.remove.ReauthenticatedAt.Equal(reauthenticatedAt) {
		t.Fatalf("disable request = %#v", credentials.remove)
	}
}

func TestAccountModuleRequiresAuthentication(t *testing.T) {
	router := accountTestRouter(t, New(Deps{Profiles: &fakeProfileManager{}}), func(c *gin.Context) {
		c.Next()
	})

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodGet, "/account/profile", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func accountTestRouter(t testing.TB, module *Module, auth gin.HandlerFunc) *gin.Engine {
	t.Helper()
	testutil.SetGinTestMode(t)

	router := gin.New()
	module.RegisterRoutes(router.Group("/account"), httpapi.Middlewares{Authenticate: auth})
	return router
}

func authenticatedAs(accountID AccountID, reauthenticatedAt time.Time) gin.HandlerFunc {
	return authenticatedAsSession(accountID, SessionID{}, reauthenticatedAt)
}

func authenticatedAsSession(accountID AccountID, sessionID SessionID, reauthenticatedAt time.Time) gin.HandlerFunc {
	return func(c *gin.Context) {
		authctx.SetAccountID(c, accountID.String())
		if !sessionID.IsZero() {
			authctx.SetSessionID(c, sessionID.String())
		}
		if !reauthenticatedAt.IsZero() {
			authctx.SetReauthenticatedAt(c, reauthenticatedAt)
		}
		c.Next()
	}
}

type fakeSessionManager struct {
	sessions        []AccountSession
	listAccountID   AccountID
	revokeAccountID AccountID
	revokeSessionID SessionID
	listErr         error
	revokeErr       error
}

func (m *fakeSessionManager) ListAccountSessions(_ context.Context, accountID AccountID) ([]AccountSession, error) {
	m.listAccountID = accountID
	if m.listErr != nil {
		return nil, m.listErr
	}
	return append([]AccountSession(nil), m.sessions...), nil
}

func (m *fakeSessionManager) RevokeAccountSession(_ context.Context, accountID AccountID, sessionID SessionID) error {
	m.revokeAccountID = accountID
	m.revokeSessionID = sessionID
	return m.revokeErr
}

type fakeProfileManager struct {
	profile AccountProfile
	update  UpdateProfileRequest
	err     error
}

func (m *fakeProfileManager) GetProfile(context.Context, AccountID) (AccountProfile, error) {
	if m.err != nil {
		return AccountProfile{}, m.err
	}
	return m.profile, nil
}

func (m *fakeProfileManager) UpdateProfile(_ context.Context, req UpdateProfileRequest) (AccountProfile, error) {
	m.update = req
	if m.err != nil {
		return AccountProfile{}, m.err
	}
	profile := m.profile
	profile.DisplayName = req.DisplayName
	profile.Metadata = req.Metadata
	return profile, nil
}

type fakeCredentialManager struct {
	credentials []Credential
	remove      RemoveCredentialRequest
	listErr     error
	removeErr   error
}

func (m *fakeCredentialManager) ListCredentials(context.Context, AccountID) ([]Credential, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.credentials, nil
}

func (m *fakeCredentialManager) RemoveCredential(_ context.Context, req RemoveCredentialRequest) (Credential, error) {
	m.remove = req
	if m.removeErr != nil {
		return Credential{}, m.removeErr
	}
	return Credential{ID: req.CredentialID, AccountID: req.AccountID}, nil
}

type fakeTOTPManager struct {
	enrollReq   TOTPEnrollmentRequest
	confirmReq  TOTPConfirmRequest
	recoveryReq RecoveryCodeGenerateRequest
	enrollment  TOTPEnrollment
	confirmed   TOTPCredential
	recovery    GeneratedRecoveryCodes
	err         error
}

func (m *fakeTOTPManager) EnrollTOTP(_ context.Context, req TOTPEnrollmentRequest) (TOTPEnrollment, error) {
	m.enrollReq = req
	if m.err != nil {
		return TOTPEnrollment{}, m.err
	}
	return m.enrollment, nil
}

func (m *fakeTOTPManager) ConfirmTOTP(_ context.Context, req TOTPConfirmRequest) (TOTPCredential, error) {
	m.confirmReq = req
	if m.err != nil {
		return TOTPCredential{}, m.err
	}
	return m.confirmed, nil
}

func (m *fakeTOTPManager) GenerateRecoveryCodes(_ context.Context, req RecoveryCodeGenerateRequest) (GeneratedRecoveryCodes, error) {
	m.recoveryReq = req
	if m.err != nil {
		return GeneratedRecoveryCodes{}, m.err
	}
	return m.recovery, nil
}

func mustCredentialSessionID(t testing.TB, value string) SessionID {
	t.Helper()
	id, err := ParseSessionID(value)
	if err != nil {
		t.Fatalf("parse session id: %v", err)
	}
	return id
}
