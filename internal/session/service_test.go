package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	gopaseto "aidanwoods.dev/go-paseto"
	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestServiceIssueSessionCreatesFullSessionAndTokens(t *testing.T) {
	now := time.Date(2026, 5, 2, 14, 30, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000801")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000802")
	refreshID := uuid.MustParse("018f1f74-10a1-7000-9000-000000000803")
	accessRandom := bytes.Repeat([]byte{0x11}, randomTokenBytes)
	refreshRandom := bytes.Repeat([]byte{0x22}, randomTokenBytes)
	random := bytes.NewReader(append(accessRandom, refreshRandom...))
	store := &fakeStore{}
	tokens := &fakeTokenIssuer{accessToken: "signed-access-token"}
	service := NewService(ServiceDeps{
		Store:  store,
		Tokens: tokens,
		Random: random,
		IDs: fixedIDs{
			sessionIDs: []account.SessionID{sessionID},
			refreshIDs: []uuid.UUID{
				refreshID,
			},
		},
		Config: Config{
			Issuer:          "https://auth.example.test",
			DefaultAudience: []string{"https://api.example.test"},
			DefaultScopes:   []string{"openid", "profile"},
			AccessTTL:       15 * time.Minute,
			RefreshSliding:  30 * 24 * time.Hour,
			RefreshAbsolute: 90 * 24 * time.Hour,
		},
	})

	result, err := service.IssueSession(context.Background(), auth.SessionIssueRequest{
		AccountID:       accountID,
		VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword, account.FactorKindPassword},
		IP:              "203.0.113.10",
		UserAgent:       "session-test",
		Now:             now,
	})
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	if result.SessionID != sessionID || result.AccessToken != "signed-access-token" || result.ExpiresAt != now.Add(15*time.Minute) {
		t.Fatalf("session result = %#v", result)
	}
	decodedRefresh, err := base64.RawURLEncoding.DecodeString(result.RefreshToken)
	if err != nil {
		t.Fatalf("decode refresh token: %v", err)
	}
	if !bytes.Equal(decodedRefresh, refreshRandom) {
		t.Fatalf("refresh token bytes = %x, want %x", decodedRefresh, refreshRandom)
	}
	refreshHash := sha256.Sum256(decodedRefresh)
	if !bytes.Equal(store.full.RefreshToken.TokenHash, refreshHash[:]) {
		t.Fatalf("stored refresh hash = %x, want %x", store.full.RefreshToken.TokenHash, refreshHash)
	}
	if bytes.Contains(store.full.RefreshToken.TokenHash, decodedRefresh) {
		t.Fatal("stored refresh token must be a hash, not token material")
	}

	if !store.fullCalled {
		t.Fatal("full session was not persisted")
	}
	if store.full.Session.ID != sessionID || store.full.Session.AccountID != accountID || store.full.Session.Kind != sessionKindFull {
		t.Fatalf("stored session = %#v", store.full.Session)
	}
	if store.full.Session.ExpiresAt != now.Add(90*24*time.Hour) {
		t.Fatalf("stored session expiry = %s", store.full.Session.ExpiresAt)
	}
	if store.full.UserAgent.FingerprintID == "" || store.full.UserAgent.IP != "203.0.113.10" || store.full.UserAgent.Description != "session-test" {
		t.Fatalf("stored user agent = %#v", store.full.UserAgent)
	}
	if got := factorKinds(store.full.Factors); !reflect.DeepEqual(got, []account.FactorKind{account.FactorKindUser, account.FactorKindPassword}) {
		t.Fatalf("stored factors = %#v", got)
	}
	if store.full.RefreshToken.ID != refreshID || store.full.RefreshToken.SessionID != sessionID {
		t.Fatalf("stored refresh token = %#v", store.full.RefreshToken)
	}

	claims := tokens.access.Claims
	if claims["sub"] != accountID.String() || claims["sid"] != sessionID.String() || claims["iss"] != "https://auth.example.test" {
		t.Fatalf("access claims = %#v", claims)
	}
	if claims["scope"] != "openid profile" {
		t.Fatalf("scope claim = %#v", claims["scope"])
	}
	if !reflect.DeepEqual(claims["aud"], []string{"https://api.example.test"}) {
		t.Fatalf("audience claim = %#v", claims["aud"])
	}
	if tokens.access.Implicit == nil || bytes.Contains(tokens.access.Implicit, []byte(result.RefreshToken)) {
		t.Fatalf("implicit assertion = %q", string(tokens.access.Implicit))
	}
}

func TestServiceRefreshSessionRotatesTokenAndIssuesReplacementTokens(t *testing.T) {
	now := time.Date(2026, 5, 2, 17, 0, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000841")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000842")
	refreshID := uuid.MustParse("018f1f74-10a1-7000-9000-000000000843")
	presentedRaw := bytes.Repeat([]byte{0x55}, randomTokenBytes)
	newRefreshRaw := bytes.Repeat([]byte{0x66}, randomTokenBytes)
	accessRandom := bytes.Repeat([]byte{0x77}, randomTokenBytes)
	presentedToken := base64.RawURLEncoding.EncodeToString(presentedRaw)
	presentedHash := sha256.Sum256(presentedRaw)
	newRefreshHash := sha256.Sum256(newRefreshRaw)
	store := &fakeStore{
		rotationResult: RefreshTokenRotationResult{
			Session: SessionRecord{
				ID:        sessionID,
				AccountID: accountID,
				Kind:      sessionKindFull,
				Status:    sessionStatusActive,
				ExpiresAt: now.Add(90 * 24 * time.Hour),
			},
			Factors: []FactorRecord{
				{SessionID: sessionID, Kind: account.FactorKindUser, VerifiedAt: now.Add(-time.Minute)},
				{SessionID: sessionID, Kind: account.FactorKindPassword, VerifiedAt: now.Add(-time.Minute)},
			},
			RefreshToken: RefreshTokenRecord{
				SessionID:         sessionID,
				Scopes:            []string{"openid", "profile", "email"},
				ExpiresAt:         now.Add(30 * 24 * time.Hour),
				AbsoluteExpiresAt: now.Add(90 * 24 * time.Hour),
			},
		},
	}
	tokens := &fakeTokenIssuer{accessToken: "refreshed-access-token"}
	service := NewService(ServiceDeps{
		Store:  store,
		Tokens: tokens,
		Random: bytes.NewReader(append(newRefreshRaw, accessRandom...)),
		IDs: fixedIDs{
			refreshIDs: []uuid.UUID{refreshID},
		},
		Config: Config{
			Issuer:          "https://auth.example.test",
			DefaultAudience: []string{"https://api.example.test"},
			AccessTTL:       15 * time.Minute,
			RefreshSliding:  30 * 24 * time.Hour,
		},
	})

	result, err := service.RefreshSession(context.Background(), RefreshSessionRequest{
		RefreshToken: presentedToken,
		Now:          now,
	})
	if err != nil {
		t.Fatalf("refresh session: %v", err)
	}

	if result.SessionID != sessionID || result.AccessToken != "refreshed-access-token" || result.ExpiresAt != now.Add(15*time.Minute) {
		t.Fatalf("refresh result = %#v", result)
	}
	if !bytes.Equal(store.rotation.TokenHash, presentedHash[:]) {
		t.Fatalf("presented hash = %x, want %x", store.rotation.TokenHash, presentedHash)
	}
	if store.rotation.NewRefreshTokenID != refreshID || !bytes.Equal(store.rotation.NewTokenHash, newRefreshHash[:]) {
		t.Fatalf("rotation = %#v", store.rotation)
	}
	if store.rotation.NewAccessTokenID == "" {
		t.Fatal("rotation did not receive replacement access token id")
	}
	decodedRefresh, err := base64.RawURLEncoding.DecodeString(result.RefreshToken)
	if err != nil {
		t.Fatalf("decode refreshed token: %v", err)
	}
	if !bytes.Equal(decodedRefresh, newRefreshRaw) {
		t.Fatalf("refreshed token bytes = %x, want %x", decodedRefresh, newRefreshRaw)
	}
	claims := tokens.access.Claims
	if claims["sub"] != accountID.String() || claims["sid"] != sessionID.String() || claims["scope"] != "openid profile email" {
		t.Fatalf("access claims = %#v", claims)
	}
	if !reflect.DeepEqual(claims["factors"], []string{"user", "password"}) {
		t.Fatalf("factors claim = %#v", claims["factors"])
	}
	if tokens.access.Implicit == nil || bytes.Contains(tokens.access.Implicit, []byte(result.RefreshToken)) {
		t.Fatalf("implicit assertion = %q", string(tokens.access.Implicit))
	}
}

func TestServiceRefreshSessionRejectsReusedToken(t *testing.T) {
	presentedRaw := bytes.Repeat([]byte{0x88}, randomTokenBytes)
	store := &fakeStore{
		rotationErr: auth.NewServiceError(auth.ErrorKindInvalidCredentials, "refresh token has already been used", nil),
	}
	tokens := &fakeTokenIssuer{accessToken: "should-not-be-issued"}
	service := NewService(ServiceDeps{
		Store:  store,
		Tokens: tokens,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x99}, randomTokenBytes*2)),
		IDs: fixedIDs{
			refreshIDs: []uuid.UUID{uuid.MustParse("018f1f74-10a1-7000-9000-000000000853")},
		},
	})

	_, err := service.RefreshSession(context.Background(), RefreshSessionRequest{
		RefreshToken: base64.RawURLEncoding.EncodeToString(presentedRaw),
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("refresh error = %v, want invalid credentials", err)
	}
	if tokens.access.Claims != nil {
		t.Fatalf("access token should not be issued after reuse: %#v", tokens.access)
	}
}

func TestServiceIssuePartialSessionCreatesBoundToken(t *testing.T) {
	now := time.Date(2026, 5, 2, 15, 0, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000811")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000812")
	random := bytes.NewReader(bytes.Repeat([]byte{0x33}, randomTokenBytes))
	store := &fakeStore{}
	tokens := &fakeTokenIssuer{partialToken: "encrypted-partial-token"}
	service := NewService(ServiceDeps{
		Store:  store,
		Tokens: tokens,
		Random: random,
		IDs: fixedIDs{
			sessionIDs: []account.SessionID{sessionID},
		},
		Config: Config{
			Issuer:     "https://auth.example.test",
			PartialTTL: 2 * time.Minute,
		},
	})

	result, err := service.IssuePartialSession(context.Background(), auth.PartialSessionIssueRequest{
		AccountID:         accountID,
		VerifiedFactors:   []account.FactorKind{account.FactorKindUser, account.FactorKindPassword},
		ChallengeBindings: []string{"password-check"},
		Now:               now,
	})
	if err != nil {
		t.Fatalf("issue partial session: %v", err)
	}

	if result.SessionID != sessionID || result.Token != "encrypted-partial-token" || result.ExpiresAt != now.Add(2*time.Minute) {
		t.Fatalf("partial result = %#v", result)
	}
	if !store.partialCalled {
		t.Fatal("partial session was not persisted")
	}
	if store.partial.Session.Kind != sessionKindPartial || store.partial.Session.TokenID == "" {
		t.Fatalf("partial session = %#v", store.partial.Session)
	}
	if got := factorKinds(store.partial.Factors); !reflect.DeepEqual(got, []account.FactorKind{account.FactorKindUser, account.FactorKindPassword}) {
		t.Fatalf("partial factors = %#v", got)
	}
	claims := tokens.partial.Claims
	if claims["typ"] != "partial_session" || claims["sub"] != accountID.String() || claims["sid"] != sessionID.String() {
		t.Fatalf("partial claims = %#v", claims)
	}
	if !reflect.DeepEqual(claims["challenge_bindings"], []string{"password-check"}) {
		t.Fatalf("challenge bindings = %#v", claims["challenge_bindings"])
	}
}

func TestServiceIssueSessionAccessTokenVerifiesWithKeystore(t *testing.T) {
	now := time.Now().UTC()
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000831")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000832")
	service := NewService(ServiceDeps{
		Store:  &fakeStore{},
		Tokens: newTestKeystore(t),
		Random: bytes.NewReader(bytes.Repeat([]byte{0x44}, randomTokenBytes*2)),
		IDs: fixedIDs{
			sessionIDs: []account.SessionID{sessionID},
			refreshIDs: []uuid.UUID{
				uuid.MustParse("018f1f74-10a1-7000-9000-000000000833"),
			},
		},
		Config: Config{
			Issuer:          "https://auth.example.test",
			DefaultAudience: []string{"https://api.example.test"},
			DefaultScopes:   []string{"openid", "profile"},
			AccessTTL:       time.Minute,
		},
	})

	result, err := service.IssueSession(context.Background(), auth.SessionIssueRequest{
		AccountID:       accountID,
		VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword},
		Now:             now,
	})
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	token, err := service.tokens.(*paseto.Keystore).VerifyAccessToken(
		context.Background(),
		result.AccessToken,
		implicitAssertion("access", accountID, sessionID, account.ClientID{}),
		gopaseto.Subject(accountID.String()),
	)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	var sid string
	if err := token.Get("sid", &sid); err != nil || sid != sessionID.String() {
		t.Fatalf("sid claim = %q, %v", sid, err)
	}
}

func TestServiceRevokeSessionCachesCurrentAccessToken(t *testing.T) {
	now := time.Date(2026, 5, 2, 19, 0, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000881")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000882")
	store := &fakeStore{
		revoked: SessionRecord{
			ID:        sessionID,
			AccountID: accountID,
			Kind:      sessionKindFull,
			Status:    sessionStatusRevoked,
			TokenID:   "access-jti",
			ExpiresAt: now.Add(90 * 24 * time.Hour),
		},
	}
	revocations := &fakeRevocationCache{}
	service := NewService(ServiceDeps{
		Store:       store,
		Revocations: revocations,
		Clock:       testutil.NewFakeClock(now),
		Config: Config{
			AccessTTL:     15 * time.Minute,
			RevocationTTL: 7 * time.Minute,
		},
	})

	result, err := service.RevokeSession(context.Background(), RevokeSessionRequest{
		SessionID: sessionID,
		AccountID: accountID,
	})
	if err != nil {
		t.Fatalf("revoke session: %v", err)
	}

	if result.SessionID != sessionID || result.AccountID != accountID || result.RevokedAt != now {
		t.Fatalf("revocation result = %#v", result)
	}
	if !store.revocationCalled || store.revocation.AccountID != accountID || store.revocation.SessionID != sessionID {
		t.Fatalf("store revocation = %#v", store.revocation)
	}
	if revocations.tokenID != "access-jti" || revocations.ttl != 7*time.Minute {
		t.Fatalf("revocation cache = token %q ttl %s", revocations.tokenID, revocations.ttl)
	}
}

func TestServiceRevokeAccountSessionsSupportsPasswordChangeRevocation(t *testing.T) {
	now := time.Date(2026, 5, 2, 19, 30, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000891")
	firstSession := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000892")
	secondSession := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000893")
	store := &fakeStore{
		accountRevoked: []SessionRecord{
			{ID: firstSession, AccountID: accountID, TokenID: "first-jti"},
			{ID: secondSession, AccountID: accountID, TokenID: "second-jti"},
		},
	}
	revocations := &fakeRevocationCache{}
	service := NewService(ServiceDeps{
		Store:       store,
		Revocations: revocations,
		Clock:       testutil.NewFakeClock(now),
		Config:      Config{AccessTTL: 15 * time.Minute},
	})

	result, err := service.RevokeAccountSessions(context.Background(), RevokeAccountSessionsRequest{AccountID: accountID})
	if err != nil {
		t.Fatalf("revoke account sessions: %v", err)
	}

	if len(result.Sessions) != 2 {
		t.Fatalf("revoked sessions length = %d, want 2", len(result.Sessions))
	}
	if !store.accountRevocationCalled || store.accountRevocation.AccountID != accountID {
		t.Fatalf("account revocation = %#v", store.accountRevocation)
	}
	if !reflect.DeepEqual(revocations.tokens, []string{"first-jti", "second-jti"}) {
		t.Fatalf("revoked token ids = %#v", revocations.tokens)
	}
	if revocations.ttl != 15*time.Minute {
		t.Fatalf("revocation ttl = %s, want 15m", revocations.ttl)
	}
}

func TestServiceAdminRevokeSessionDoesNotRequireAccountScope(t *testing.T) {
	now := time.Date(2026, 5, 2, 20, 0, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000901")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000902")
	store := &fakeStore{
		revoked: SessionRecord{
			ID:        sessionID,
			AccountID: accountID,
			TokenID:   "admin-revoked-jti",
		},
	}
	service := NewService(ServiceDeps{
		Store:       store,
		Revocations: &fakeRevocationCache{},
		Clock:       testutil.NewFakeClock(now),
	})

	result, err := service.AdminRevokeSession(context.Background(), AdminRevokeSessionRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("admin revoke session: %v", err)
	}
	if result.SessionID != sessionID || result.AccountID != accountID {
		t.Fatalf("admin revoke result = %#v", result)
	}
	if !store.revocationCalled || !store.revocation.AccountID.IsZero() {
		t.Fatalf("admin store revocation = %#v", store.revocation)
	}
}

func TestServiceIssueSessionValidatesRequiredDependencies(t *testing.T) {
	service := NewService(ServiceDeps{})

	_, err := service.IssueSession(context.Background(), auth.SessionIssueRequest{
		AccountID: mustAccountID(t, "018f1f74-10a1-7000-9000-000000000821"),
	})
	if !errors.Is(err, auth.ErrInternal) {
		t.Fatalf("issue session error = %v, want internal", err)
	}

	service = NewService(ServiceDeps{Store: &fakeStore{}, Tokens: &fakeTokenIssuer{accessToken: "token"}})
	_, err = service.IssueSession(context.Background(), auth.SessionIssueRequest{})
	if !errors.Is(err, auth.ErrMalformedInput) {
		t.Fatalf("missing account error = %v, want malformed input", err)
	}
}

type fakeStore struct {
	fullCalled              bool
	partialCalled           bool
	rotationCalled          bool
	revocationCalled        bool
	accountRevocationCalled bool
	full                    FullSessionRecord
	partial                 PartialSessionRecord
	rotation                RefreshTokenRotation
	revocation              SessionRevocation
	accountRevocation       AccountSessionsRevocation
	rotationResult          RefreshTokenRotationResult
	revoked                 SessionRecord
	accountRevoked          []SessionRecord
	rotationErr             error
}

func (s *fakeStore) CreateFullSession(_ context.Context, record FullSessionRecord) error {
	s.fullCalled = true
	s.full = record
	return nil
}

func (s *fakeStore) CreatePartialSession(_ context.Context, record PartialSessionRecord) error {
	s.partialCalled = true
	s.partial = record
	return nil
}

func (s *fakeStore) GetActiveSession(_ context.Context, sessionID account.SessionID, _ time.Time) (SessionRecord, error) {
	if s.revoked.ID == sessionID {
		return s.revoked, nil
	}
	return SessionRecord{}, auth.ErrInvalidCredentials
}

func (s *fakeStore) RevokeSession(_ context.Context, revocation SessionRevocation) (SessionRecord, error) {
	s.revocationCalled = true
	s.revocation = revocation
	if s.revoked.ID.IsZero() {
		return SessionRecord{}, auth.ErrInvalidCredentials
	}
	return s.revoked, nil
}

func (s *fakeStore) RevokeAccountSessions(_ context.Context, revocation AccountSessionsRevocation) ([]SessionRecord, error) {
	s.accountRevocationCalled = true
	s.accountRevocation = revocation
	return append([]SessionRecord(nil), s.accountRevoked...), nil
}

func (s *fakeStore) RotateRefreshToken(_ context.Context, rotation RefreshTokenRotation) (RefreshTokenRotationResult, error) {
	s.rotationCalled = true
	s.rotation = rotation
	if s.rotationErr != nil {
		return RefreshTokenRotationResult{}, s.rotationErr
	}
	result := s.rotationResult
	result.RefreshToken.ID = rotation.NewRefreshTokenID
	result.RefreshToken.TokenHash = append([]byte(nil), rotation.NewTokenHash...)
	return result, nil
}

type fakeRevocationCache struct {
	tokenID string
	tokens  []string
	ttl     time.Duration
	revoked bool
	err     error
}

func (c *fakeRevocationCache) RevokeAccessToken(_ context.Context, tokenID string, ttl time.Duration) error {
	c.tokenID = tokenID
	c.tokens = append(c.tokens, tokenID)
	c.ttl = ttl
	return c.err
}

func (c *fakeRevocationCache) IsAccessTokenRevoked(context.Context, string) (bool, error) {
	return c.revoked, c.err
}

type fakeTokenIssuer struct {
	accessToken  string
	partialToken string
	access       paseto.IssueRequest
	partial      paseto.IssueRequest
}

func (i *fakeTokenIssuer) IssueAccessToken(_ context.Context, req paseto.IssueRequest) (string, error) {
	i.access = req
	return i.accessToken, nil
}

func (i *fakeTokenIssuer) IssuePartialSessionToken(_ context.Context, req paseto.IssueRequest) (string, error) {
	i.partial = req
	return i.partialToken, nil
}

type fixedIDs struct {
	sessionIDs []account.SessionID
	refreshIDs []uuid.UUID
}

func (g fixedIDs) NewSessionID() (account.SessionID, error) {
	if len(g.sessionIDs) == 0 {
		return account.SessionID{}, errors.New("no session ids")
	}
	return g.sessionIDs[0], nil
}

func (g fixedIDs) NewRefreshTokenID() (uuid.UUID, error) {
	if len(g.refreshIDs) == 0 {
		return uuid.Nil, errors.New("no refresh ids")
	}
	return g.refreshIDs[0], nil
}

func factorKinds(records []FactorRecord) []account.FactorKind {
	kinds := make([]account.FactorKind, 0, len(records))
	for _, record := range records {
		kinds = append(kinds, record.Kind)
	}
	return kinds
}

func mustAccountID(t *testing.T, value string) account.AccountID {
	t.Helper()
	id, err := account.ParseAccountID(value)
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	return id
}

func mustSessionID(t *testing.T, value string) account.SessionID {
	t.Helper()
	id, err := account.ParseSessionID(value)
	if err != nil {
		t.Fatalf("parse session id: %v", err)
	}
	return id
}

func newTestKeystore(t testing.TB) *paseto.Keystore {
	t.Helper()
	ks, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{}, testutil.StaticSecrets{
		"env://LOCAL": bytes.Repeat([]byte{0x11}, 32),
		"env://SEED":  bytes.Repeat([]byte{0x22}, 32),
	}, paseto.Refs{
		LocalKey:   "env://LOCAL",
		PublicSeed: "env://SEED",
	})
	if err != nil {
		t.Fatalf("new keystore: %v", err)
	}
	return ks
}
