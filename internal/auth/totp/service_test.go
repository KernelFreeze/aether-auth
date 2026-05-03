package totp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

func TestRFC6238ValidationAllowsOneWindow(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(59, 0).UTC()
	code, err := GenerateCode(secret, now, 8, 30*time.Second)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if code != "94287082" {
		t.Fatalf("code = %q, want RFC vector", code)
	}

	ok, err := ValidateCode(secret, code, now.Add(30*time.Second), 8, 30*time.Second, 1)
	if err != nil {
		t.Fatalf("validate code: %v", err)
	}
	if !ok {
		t.Fatal("code should validate in the adjacent time window")
	}
	ok, err = ValidateCode(secret, code, now.Add(2*30*time.Second), 8, 30*time.Second, 1)
	if err != nil {
		t.Fatalf("validate stale code: %v", err)
	}
	if ok {
		t.Fatal("code should not validate outside the one-window tolerance")
	}
}

func TestEnrollAndConfirmTOTP(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000002001")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000002002")
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	repo := &fakeCredentialRepository{nextID: credentialID}
	attempts := &fakeAttemptStore{}
	service := New(Deps{
		Credentials: repo,
		Box:         fakeSecretBox{},
		Attempts:    attempts,
		Clock:       fakeClock{now: now},
		Random:      bytes.NewReader(bytes.Repeat([]byte{0x11}, defaultSecretSize)),
		Config:      Config{Issuer: "Aether Auth"},
	})

	enrollment, err := service.Enroll(context.Background(), EnrollRequest{
		AccountID:   accountID,
		AccountName: "celeste",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if enrollment.CredentialID != credentialID || !strings.HasPrefix(enrollment.ProvisioningURI, "otpauth://totp/") {
		t.Fatalf("enrollment = %#v", enrollment)
	}
	if repo.create.Kind != account.CredentialKindTOTP || repo.create.Verified {
		t.Fatalf("created credential = %#v", repo.create)
	}

	code, err := GenerateCode(enrollment.Secret, now, defaultDigits, defaultPeriod)
	if err != nil {
		t.Fatalf("generate setup code: %v", err)
	}
	updated, err := service.ConfirmEnrollment(context.Background(), ConfirmEnrollmentRequest{
		AccountID:    accountID,
		CredentialID: credentialID,
		Code:         code,
	})
	if err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	if !updated.Verified || repo.update.CredentialID != credentialID || repo.update.LastUsedAt != now {
		t.Fatalf("updated credential = %#v / update %#v", updated, repo.update)
	}
	if attempts.success.Factor != account.FactorKindTOTP {
		t.Fatalf("success attempt = %#v", attempts.success)
	}
}

func TestVerifyTOTPLockoutOnRepeatedFailure(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000002003")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000002004")
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	repo := &fakeCredentialRepository{}
	service := New(Deps{
		Credentials: repo,
		Box:         fakeSecretBox{},
		Attempts: &fakeAttemptStore{
			failure: AttemptResult{FailedCount: 5, LockedUntil: now.Add(time.Minute)},
		},
		Clock: fakeClock{now: now},
	})
	payload, err := service.sealSecret(context.Background(), accountID, storedTOTPPayload{
		Secret:        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		Algorithm:     algorithmSHA1,
		Digits:        defaultDigits,
		PeriodSeconds: int(defaultPeriod / time.Second),
	})
	if err != nil {
		t.Fatalf("seal secret: %v", err)
	}
	repo.lookup = auth.CredentialSnapshot{
		ID:               credentialID,
		AccountID:        accountID,
		Kind:             account.CredentialKindTOTP,
		EncryptedPayload: payload,
		Verified:         true,
	}

	_, _, err = service.VerifyTOTP(context.Background(), VerifyTOTPRequest{
		AccountID: accountID,
		Code:      "654321",
		IP:        netip.MustParseAddr("203.0.113.30"),
	})
	if !errors.Is(err, auth.ErrLockedAccount) {
		t.Fatalf("verify error = %v, want locked account", err)
	}
}

func TestVerifyTOTPFailureWritesAuditWithoutCode(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000002007")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000002008")
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	audit := &fakeAuditWriter{}
	repo := &fakeCredentialRepository{}
	service := New(Deps{
		Credentials: repo,
		Box:         fakeSecretBox{},
		Attempts:    &fakeAttemptStore{},
		Audit:       audit,
		Clock:       fakeClock{now: now},
	})
	payload, err := service.sealSecret(context.Background(), accountID, storedTOTPPayload{
		Secret:        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		Algorithm:     algorithmSHA1,
		Digits:        defaultDigits,
		PeriodSeconds: int(defaultPeriod / time.Second),
	})
	if err != nil {
		t.Fatalf("seal secret: %v", err)
	}
	repo.lookup = auth.CredentialSnapshot{
		ID:               credentialID,
		AccountID:        accountID,
		Kind:             account.CredentialKindTOTP,
		EncryptedPayload: payload,
		Verified:         true,
	}

	_, _, err = service.VerifyTOTP(context.Background(), VerifyTOTPRequest{
		AccountID: accountID,
		Code:      "000000",
		RequestID: "req-mfa-fail",
		IP:        netip.MustParseAddr("203.0.113.31"),
		UserAgent: "mfa-test-agent",
		Endpoint:  "/auth/mfa/verify",
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("verify error = %v, want invalid credentials", err)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events length = %d, want 1", len(audit.events))
	}
	event := audit.events[0]
	if event.Type != auth.AuditEventMFAFailed || event.AccountID != accountID || event.CredentialID != credentialID {
		t.Fatalf("audit event = %#v", event)
	}
	if event.RequestID != "req-mfa-fail" || event.IP != "203.0.113.31" || event.UserAgent != "mfa-test-agent" {
		t.Fatalf("audit request context = %#v", event)
	}
	if event.Attributes["factor"] != account.FactorKindTOTP.String() || event.Attributes["outcome"] != "invalid" || event.Attributes["endpoint"] != "/auth/mfa/verify" {
		t.Fatalf("audit attributes = %#v", event.Attributes)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal audit event: %v", err)
	}
	for _, forbidden := range []string{"654321", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("audit event leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestRecoveryCodesGenerateConsumeAndRejectReplay(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000002005")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000002006")
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	repo := &fakeCredentialRepository{nextID: credentialID}
	store := &fakeRecoveryCodeStore{}
	attempts := &fakeAttemptStore{}
	service := New(Deps{
		Credentials:   repo,
		RecoveryCodes: store,
		Hasher:        fakeRecoveryHasher{},
		Attempts:      attempts,
		Clock:         fakeClock{now: now},
		Random:        incrementingReader{},
		Config: Config{
			RecoveryCodeCount:    1,
			RecoveryCodeLength:   4,
			RecoveryCodeAlphabet: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
		},
	})

	generated, err := service.GenerateRecoveryCodes(context.Background(), GenerateRecoveryCodesRequest{AccountID: accountID})
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}
	if generated.CredentialID != credentialID || len(generated.Codes) != 1 || len(generated.Records) != 1 {
		t.Fatalf("generated = %#v", generated)
	}
	if store.set.AccountID != accountID || !bytes.HasPrefix(store.set.CodeHashes[0], []byte("hash:")) {
		t.Fatalf("stored code set = %#v", store.set)
	}

	replayInput := strings.ToLower(generated.Codes[0][:2] + "-" + generated.Codes[0][2:])
	check, _, err := service.VerifyRecoveryCode(context.Background(), VerifyRecoveryCodeRequest{
		AccountID:        accountID,
		Code:             replayInput,
		ChallengeBinding: "partial-session",
	})
	if err != nil {
		t.Fatalf("verify recovery code: %v", err)
	}
	if check.Kind != account.FactorKindRecoveryCode || !check.Verified() || check.ChallengeBinding != "partial-session" {
		t.Fatalf("factor check = %#v", check)
	}
	if len(store.consumed) != 1 || attempts.success.Factor != account.FactorKindRecoveryCode {
		t.Fatalf("consume/success = %#v / %#v", store.consumed, attempts.success)
	}

	_, _, err = service.VerifyRecoveryCode(context.Background(), VerifyRecoveryCodeRequest{
		AccountID: accountID,
		Code:      generated.Codes[0],
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("replay error = %v, want invalid credentials", err)
	}
	if attempts.fail.Factor != account.FactorKindRecoveryCode {
		t.Fatalf("replay failure = %#v", attempts.fail)
	}
}

type fakeCredentialRepository struct {
	nextID account.CredentialID
	lookup auth.CredentialSnapshot
	create auth.CredentialDraft
	update auth.CredentialUpdate
}

func (r *fakeCredentialRepository) LookupCredential(_ context.Context, lookup auth.CredentialLookup) (auth.CredentialSnapshot, error) {
	if !r.lookup.ID.IsZero() {
		return r.lookup, nil
	}
	if lookup.Kind == account.CredentialKindRecoveryCode && !r.nextID.IsZero() && r.create.Kind == account.CredentialKindRecoveryCode {
		return auth.CredentialSnapshot{
			ID:        r.nextID,
			AccountID: r.create.AccountID,
			Kind:      r.create.Kind,
			Verified:  r.create.Verified,
		}, nil
	}
	return auth.CredentialSnapshot{}, auth.ErrInvalidCredentials
}

func (r *fakeCredentialRepository) CreateCredential(_ context.Context, draft auth.CredentialDraft) (auth.CredentialSnapshot, error) {
	r.create = draft
	id := r.nextID
	if id.IsZero() {
		id = mustCredentialIDNoT("018f1f74-10a1-7000-9000-000000002099")
	}
	r.lookup = auth.CredentialSnapshot{
		ID:               id,
		AccountID:        draft.AccountID,
		Kind:             draft.Kind,
		EncryptedPayload: append([]byte(nil), draft.EncryptedPayload...),
		Verified:         draft.Verified,
	}
	return r.lookup, nil
}

func (r *fakeCredentialRepository) UpdateCredential(_ context.Context, update auth.CredentialUpdate) (auth.CredentialSnapshot, error) {
	r.update = update
	if !update.CredentialID.IsZero() {
		r.lookup.ID = update.CredentialID
	}
	if len(update.EncryptedPayload) > 0 {
		r.lookup.EncryptedPayload = append([]byte(nil), update.EncryptedPayload...)
	}
	if update.Verified != nil {
		r.lookup.Verified = *update.Verified
	}
	r.lookup.LastUsedAt = update.LastUsedAt
	return r.lookup, nil
}

func (r *fakeCredentialRepository) CanRemoveCredential(context.Context, account.AccountID, account.CredentialID) (bool, error) {
	return true, nil
}

type fakeRecoveryCodeStore struct {
	set      RecoveryCodeSet
	records  []RecoveryCodeRecord
	consumed []uuid.UUID
}

func (s *fakeRecoveryCodeStore) ReplaceRecoveryCodes(_ context.Context, set RecoveryCodeSet) ([]RecoveryCodeRecord, error) {
	s.set = set
	s.records = make([]RecoveryCodeRecord, 0, len(set.CodeHashes))
	for i, hash := range set.CodeHashes {
		s.records = append(s.records, RecoveryCodeRecord{
			ID:           uuid.MustParse("018f1f74-10a1-7000-9000-00000000210" + string(rune('0'+i))),
			AccountID:    set.AccountID,
			CredentialID: set.CredentialID,
			CodeHash:     append([]byte(nil), hash...),
		})
	}
	return append([]RecoveryCodeRecord(nil), s.records...), nil
}

func (s *fakeRecoveryCodeStore) ListUnusedRecoveryCodes(context.Context, account.AccountID, account.CredentialID) ([]RecoveryCodeRecord, error) {
	records := make([]RecoveryCodeRecord, 0, len(s.records))
	for _, record := range s.records {
		if record.UsedAt.IsZero() {
			records = append(records, record)
		}
	}
	return records, nil
}

func (s *fakeRecoveryCodeStore) ConsumeRecoveryCode(_ context.Context, consumption RecoveryCodeConsumption) (RecoveryCodeRecord, error) {
	for i, record := range s.records {
		if record.ID == consumption.ID && record.UsedAt.IsZero() {
			record.UsedAt = consumption.UsedAt
			s.records[i] = record
			s.consumed = append(s.consumed, consumption.ID)
			return record, nil
		}
	}
	return RecoveryCodeRecord{}, auth.ErrInvalidCredentials
}

type fakeRecoveryHasher struct{}

func (fakeRecoveryHasher) HashPassword(_ context.Context, req auth.PasswordHashRequest) (auth.PasswordHash, error) {
	return auth.PasswordHash{PHCString: "hash:" + req.Password}, nil
}

func (fakeRecoveryHasher) VerifyPassword(_ context.Context, req auth.PasswordVerifyRequest) (auth.PasswordVerifyResult, error) {
	return auth.PasswordVerifyResult{Matched: req.Hash.PHCString == "hash:"+req.Password}, nil
}

type fakeSecretBox struct{}

func (fakeSecretBox) Seal(_ context.Context, req auth.SecretBoxSealRequest) (auth.SecretBoxPayload, error) {
	return auth.SecretBoxPayload{KeyID: "test", Ciphertext: append([]byte("sealed:"), req.Plaintext...)}, nil
}

func (fakeSecretBox) Open(_ context.Context, req auth.SecretBoxOpenRequest) ([]byte, error) {
	return bytes.TrimPrefix(req.Payload.Ciphertext, []byte("sealed:")), nil
}

type fakeAttemptStore struct {
	failure AttemptResult
	fail    AttemptFailure
	success AttemptSuccess
}

func (s *fakeAttemptStore) RecordFailure(_ context.Context, failure AttemptFailure) (AttemptResult, error) {
	s.fail = failure
	return s.failure, nil
}

func (s *fakeAttemptStore) RecordSuccess(_ context.Context, success AttemptSuccess) error {
	s.success = success
	return nil
}

type fakeAuditWriter struct {
	events []auth.AuditEvent
}

func (w *fakeAuditWriter) WriteAuditEvent(_ context.Context, event auth.AuditEvent) error {
	w.events = append(w.events, event)
	return nil
}

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time {
	return c.now
}

type incrementingReader struct{}

func (incrementingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}

var _ io.Reader = incrementingReader{}

func mustAccountID(t testing.TB, value string) account.AccountID {
	t.Helper()
	id, err := account.ParseAccountID(value)
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	return id
}

func mustCredentialID(t testing.TB, value string) account.CredentialID {
	t.Helper()
	id, err := account.ParseCredentialID(value)
	if err != nil {
		t.Fatalf("parse credential id: %v", err)
	}
	return id
}

func mustCredentialIDNoT(value string) account.CredentialID {
	id, err := account.ParseCredentialID(value)
	if err != nil {
		panic(err)
	}
	return id
}
