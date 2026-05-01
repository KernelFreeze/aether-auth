package auth

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

func TestCrossFeatureInterfacesSupportSmallFakes(t *testing.T) {
	ctx := context.Background()
	accountID, credentialID := mustAuthIDs(t)
	sessionID := mustSessionID(t)
	clientID := mustClientID(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	accounts := fakeAccountRepository{
		snapshot: AccountSnapshot{
			ID:          accountID,
			Username:    "celeste",
			DisplayName: "Celeste",
			MFARequired: true,
		},
		state: AccountState{
			AccountID:   accountID,
			LockedUntil: now.Add(time.Minute),
			MFARequired: true,
		},
	}
	snapshot, err := accounts.LookupAccount(ctx, AccountLookup{Username: "celeste"})
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}
	if snapshot.ID != accountID {
		t.Fatalf("account ID = %v, want %v", snapshot.ID, accountID)
	}
	state, err := accounts.AccountState(ctx, accountID)
	if err != nil {
		t.Fatalf("account state: %v", err)
	}
	if !state.Locked(now) {
		t.Fatal("account should be locked before LockedUntil")
	}
	if state.Locked(now.Add(2 * time.Minute)) {
		t.Fatal("account should be unlocked after LockedUntil")
	}

	credentials := fakeCredentialRepository{
		credential: CredentialSnapshot{
			ID:               credentialID,
			AccountID:        accountID,
			Kind:             account.CredentialKindPassword,
			EncryptedPayload: []byte("ciphertext"),
			Verified:         true,
		},
		canRemove: false,
	}
	credential, err := credentials.LookupCredential(ctx, CredentialLookup{
		AccountID: accountID,
		Kind:      account.CredentialKindPassword,
	})
	if err != nil {
		t.Fatalf("lookup credential: %v", err)
	}
	if credential.ID != credentialID {
		t.Fatalf("credential ID = %v, want %v", credential.ID, credentialID)
	}
	canRemove, err := credentials.CanRemoveCredential(ctx, accountID, credentialID)
	if err != nil {
		t.Fatalf("can remove credential: %v", err)
	}
	if canRemove {
		t.Fatal("last credential should not be removable")
	}

	challenges := fakeChallengeStore{
		challenge: StoredChallenge{
			ID:             "chal_123",
			Purpose:        ChallengePurposeWebAuthn,
			AccountID:      accountID,
			SessionBinding: "binding",
			Payload:        []byte("challenge"),
			ExpiresAt:      now.Add(time.Minute),
		},
	}
	if err := challenges.SaveChallenge(ctx, challenges.challenge); err != nil {
		t.Fatalf("save challenge: %v", err)
	}
	challenge, err := challenges.ConsumeChallenge(ctx, ChallengeLookup{
		ID:             "chal_123",
		Purpose:        ChallengePurposeWebAuthn,
		SessionBinding: "binding",
	})
	if err != nil {
		t.Fatalf("consume challenge: %v", err)
	}
	if !bytes.Equal(challenge.Payload, []byte("challenge")) {
		t.Fatalf("challenge payload = %q, want challenge", challenge.Payload)
	}

	factors := fakeFactorStore{
		state: PartialSessionState{
			SessionID:       sessionID,
			AccountID:       accountID,
			VerifiedFactors: []account.FactorKind{account.FactorKindUser},
			ExpiresAt:       now.Add(2 * time.Minute),
		},
	}
	partial, err := factors.AddVerifiedFactor(ctx, sessionID, account.FactorKindPassword, "password")
	if err != nil {
		t.Fatalf("add verified factor: %v", err)
	}
	if len(partial.VerifiedFactors) != 2 {
		t.Fatalf("verified factors = %d, want 2", len(partial.VerifiedFactors))
	}

	sessions := fakeSessionIssuer{
		full: SessionIssueResult{
			SessionID:    sessionID,
			AccessToken:  "access",
			RefreshToken: "refresh",
			ExpiresAt:    now.Add(15 * time.Minute),
		},
		partial: PartialSessionIssueResult{
			SessionID: sessionID,
			Token:     "partial",
			ExpiresAt: now.Add(2 * time.Minute),
		},
	}
	fullSession, err := sessions.IssueSession(ctx, SessionIssueRequest{
		AccountID:       accountID,
		ClientID:        clientID,
		VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword},
		Now:             now,
	})
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	if fullSession.AccessToken == "" || fullSession.RefreshToken == "" {
		t.Fatal("full session should include access and refresh tokens")
	}
	partialSession, err := sessions.IssuePartialSession(ctx, PartialSessionIssueRequest{
		AccountID: accountID,
		TTL:       2 * time.Minute,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("issue partial session: %v", err)
	}
	if partialSession.Token == "" {
		t.Fatal("partial session should include a token")
	}

	audit := &fakeAuditWriter{}
	if err := audit.WriteAuditEvent(ctx, AuditEvent{
		Type:       "auth.login.succeeded",
		AccountID:  accountID,
		OccurredAt: now,
	}); err != nil {
		t.Fatalf("write audit event: %v", err)
	}
	if audit.wrote != "auth.login.succeeded" {
		t.Fatalf("audit event = %q, want auth.login.succeeded", audit.wrote)
	}

	limiter := fakeRateLimiter{result: RateLimitResult{Allowed: true, Limit: 10, Remaining: 9}}
	limit, err := limiter.CheckRateLimit(ctx, RateLimitRequest{
		Subject: RateLimitSubject{AccountID: accountID, Endpoint: "/auth/login"},
		Cost:    1,
		Now:     now,
	})
	if err != nil {
		t.Fatalf("check rate limit: %v", err)
	}
	if !limit.Allowed {
		t.Fatal("rate limit should allow the request")
	}

	clock := fakeClock{now: now}
	if got := clock.Now(); !got.Equal(now) {
		t.Fatalf("clock now = %v, want %v", got, now)
	}
	random := fakeRandomReader{data: []byte{1, 2, 3}}
	buf := make([]byte, 3)
	if _, err := random.Read(buf); err != nil {
		t.Fatalf("read random: %v", err)
	}
	if !bytes.Equal(buf, []byte{1, 2, 3}) {
		t.Fatalf("random bytes = %v, want [1 2 3]", buf)
	}

	ids := fakeIDGenerator{
		accountID:    accountID,
		credentialID: credentialID,
		sessionID:    sessionID,
		clientID:     clientID,
		challengeID:  "chal_123",
	}
	generatedAccountID, err := ids.NewAccountID()
	if err != nil {
		t.Fatalf("new account ID: %v", err)
	}
	if generatedAccountID != accountID {
		t.Fatalf("generated account ID = %v, want %v", generatedAccountID, accountID)
	}

	passwords := fakePasswordHasher{
		hash:   PasswordHash{PHCString: "$argon2id$v=19$m=19456,t=2,p=1$...", ParamsID: "argon2id-2026-05"},
		verify: PasswordVerifyResult{Matched: true},
	}
	hash, err := passwords.HashPassword(ctx, PasswordHashRequest{Password: "correct horse battery staple", AccountID: accountID})
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	verify, err := passwords.VerifyPassword(ctx, PasswordVerifyRequest{Password: "correct horse battery staple", Hash: hash, AccountID: accountID})
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !verify.Matched {
		t.Fatal("password should match")
	}

	policy := fakePasswordPolicy{result: PasswordPolicyResult{Allowed: true}}
	policyResult, err := policy.CheckPasswordPolicy(ctx, PasswordPolicyRequest{
		Password:  "correct horse battery staple",
		AccountID: accountID,
		Username:  "celeste",
	})
	if err != nil {
		t.Fatalf("check password policy: %v", err)
	}
	if !policyResult.Allowed {
		t.Fatal("password policy should allow the password")
	}

	breaches := fakeBreachChecker{result: PasswordBreachResult{Breached: false}}
	breach, err := breaches.CheckPasswordBreach(ctx, PasswordBreachRequest{
		Password:  "correct horse battery staple",
		AccountID: accountID,
	})
	if err != nil {
		t.Fatalf("check password breach: %v", err)
	}
	if breach.Breached {
		t.Fatal("password should not be breached")
	}

	box := fakeSecretBox{payload: SecretBoxPayload{
		KeyID:      "key-1",
		Nonce:      []byte("nonce"),
		Ciphertext: []byte("ciphertext"),
	}}
	sealed, err := box.Seal(ctx, SecretBoxSealRequest{Plaintext: []byte("secret"), KeyID: "key-1"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := box.Open(ctx, SecretBoxOpenRequest{Payload: sealed})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, []byte("secret")) {
		t.Fatalf("opened plaintext = %q, want secret", opened)
	}
}

func TestAccountStateLockedTreatsZeroLockedUntilAsUnlocked(t *testing.T) {
	var state AccountState
	if state.Locked(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("zero LockedUntil should be unlocked")
	}
}

type fakeAccountRepository struct {
	snapshot AccountSnapshot
	state    AccountState
}

var _ AccountRepository = fakeAccountRepository{}

func (r fakeAccountRepository) LookupAccount(context.Context, AccountLookup) (AccountSnapshot, error) {
	return r.snapshot, nil
}

func (r fakeAccountRepository) AccountState(context.Context, account.AccountID) (AccountState, error) {
	return r.state, nil
}

type fakeCredentialRepository struct {
	credential CredentialSnapshot
	canRemove  bool
}

var _ CredentialRepository = fakeCredentialRepository{}

func (r fakeCredentialRepository) LookupCredential(context.Context, CredentialLookup) (CredentialSnapshot, error) {
	return r.credential, nil
}

func (r fakeCredentialRepository) CreateCredential(context.Context, CredentialDraft) (CredentialSnapshot, error) {
	return r.credential, nil
}

func (r fakeCredentialRepository) UpdateCredential(context.Context, CredentialUpdate) (CredentialSnapshot, error) {
	return r.credential, nil
}

func (r fakeCredentialRepository) CanRemoveCredential(context.Context, account.AccountID, account.CredentialID) (bool, error) {
	return r.canRemove, nil
}

type fakeChallengeStore struct {
	challenge StoredChallenge
}

var _ ChallengeStore = fakeChallengeStore{}

func (s fakeChallengeStore) SaveChallenge(context.Context, StoredChallenge) error {
	return nil
}

func (s fakeChallengeStore) ConsumeChallenge(context.Context, ChallengeLookup) (StoredChallenge, error) {
	return s.challenge, nil
}

func (s fakeChallengeStore) DeleteExpiredChallenges(context.Context, time.Time) error {
	return nil
}

type fakeFactorStore struct {
	state PartialSessionState
}

var _ FactorStore = fakeFactorStore{}

func (s fakeFactorStore) SavePartialSession(context.Context, PartialSessionState) error {
	return nil
}

func (s fakeFactorStore) GetPartialSession(context.Context, account.SessionID) (PartialSessionState, error) {
	return s.state, nil
}

func (s fakeFactorStore) AddVerifiedFactor(_ context.Context, _ account.SessionID, factor account.FactorKind, binding string) (PartialSessionState, error) {
	state := s.state
	state.VerifiedFactors = append(append([]account.FactorKind(nil), state.VerifiedFactors...), factor)
	state.ChallengeBindings = append(append([]string(nil), state.ChallengeBindings...), binding)
	return state, nil
}

func (s fakeFactorStore) DeletePartialSession(context.Context, account.SessionID) error {
	return nil
}

type fakeSessionIssuer struct {
	full    SessionIssueResult
	partial PartialSessionIssueResult
}

var _ SessionIssuer = fakeSessionIssuer{}

func (i fakeSessionIssuer) IssueSession(context.Context, SessionIssueRequest) (SessionIssueResult, error) {
	return i.full, nil
}

func (i fakeSessionIssuer) IssuePartialSession(context.Context, PartialSessionIssueRequest) (PartialSessionIssueResult, error) {
	return i.partial, nil
}

type fakeAuditWriter struct {
	wrote string
}

var _ AuditWriter = (*fakeAuditWriter)(nil)

func (w *fakeAuditWriter) WriteAuditEvent(_ context.Context, event AuditEvent) error {
	w.wrote = event.Type
	return nil
}

type fakeRateLimiter struct {
	result RateLimitResult
}

var _ RateLimiter = fakeRateLimiter{}

func (l fakeRateLimiter) CheckRateLimit(context.Context, RateLimitRequest) (RateLimitResult, error) {
	return l.result, nil
}

type fakeClock struct {
	now time.Time
}

var _ Clock = fakeClock{}

func (c fakeClock) Now() time.Time {
	return c.now
}

type fakeRandomReader struct {
	data []byte
}

var _ RandomReader = fakeRandomReader{}

func (r fakeRandomReader) Read(p []byte) (int, error) {
	return copy(p, r.data), nil
}

type fakeIDGenerator struct {
	accountID      account.AccountID
	credentialID   account.CredentialID
	sessionID      account.SessionID
	organizationID account.OrganizationID
	clientID       account.ClientID
	challengeID    string
}

var _ IDGenerator = fakeIDGenerator{}

func (g fakeIDGenerator) NewAccountID() (account.AccountID, error) {
	return g.accountID, nil
}

func (g fakeIDGenerator) NewCredentialID() (account.CredentialID, error) {
	return g.credentialID, nil
}

func (g fakeIDGenerator) NewSessionID() (account.SessionID, error) {
	return g.sessionID, nil
}

func (g fakeIDGenerator) NewOrganizationID() (account.OrganizationID, error) {
	return g.organizationID, nil
}

func (g fakeIDGenerator) NewClientID() (account.ClientID, error) {
	return g.clientID, nil
}

func (g fakeIDGenerator) NewChallengeID() (string, error) {
	return g.challengeID, nil
}

type fakePasswordHasher struct {
	hash   PasswordHash
	verify PasswordVerifyResult
}

var _ PasswordHasher = fakePasswordHasher{}

func (h fakePasswordHasher) HashPassword(context.Context, PasswordHashRequest) (PasswordHash, error) {
	return h.hash, nil
}

func (h fakePasswordHasher) VerifyPassword(context.Context, PasswordVerifyRequest) (PasswordVerifyResult, error) {
	return h.verify, nil
}

type fakePasswordPolicy struct {
	result PasswordPolicyResult
}

var _ PasswordPolicy = fakePasswordPolicy{}

func (p fakePasswordPolicy) CheckPasswordPolicy(context.Context, PasswordPolicyRequest) (PasswordPolicyResult, error) {
	return p.result, nil
}

type fakeBreachChecker struct {
	result PasswordBreachResult
}

var _ BreachChecker = fakeBreachChecker{}

func (c fakeBreachChecker) CheckPasswordBreach(context.Context, PasswordBreachRequest) (PasswordBreachResult, error) {
	return c.result, nil
}

type fakeSecretBox struct {
	payload SecretBoxPayload
}

var _ SecretBox = fakeSecretBox{}

func (b fakeSecretBox) Seal(context.Context, SecretBoxSealRequest) (SecretBoxPayload, error) {
	return b.payload, nil
}

func (b fakeSecretBox) Open(context.Context, SecretBoxOpenRequest) ([]byte, error) {
	return []byte("secret"), nil
}

func mustSessionID(t *testing.T) account.SessionID {
	t.Helper()

	id, err := account.ParseSessionID("018f1f47-4000-7c09-8d93-9f12a5e0a333")
	if err != nil {
		t.Fatalf("parse session ID: %v", err)
	}
	return id
}

func mustClientID(t *testing.T) account.ClientID {
	t.Helper()

	id, err := account.ParseClientID("018f1f47-4000-7c09-8d93-9f12a5e0a444")
	if err != nil {
		t.Fatalf("parse client ID: %v", err)
	}
	return id
}
