package mfa

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

func TestSessionFactorsTrackVerifiedAndFailedChecks(t *testing.T) {
	now := time.Date(2026, 5, 3, 13, 0, 0, 0, time.UTC)
	accountID := account.AccountID(uuid.MustParse("018f1f74-10a1-7000-9000-000000001001"))
	var factors SessionFactors

	var err error
	factors, err = factors.MarkUserVerified(accountID, now)
	if err != nil {
		t.Fatalf("mark user verified: %v", err)
	}
	factors, err = factors.MarkPasswordVerified(now.Add(time.Second), "password-check")
	if err != nil {
		t.Fatalf("mark password verified: %v", err)
	}
	factors, err = factors.MarkTOTPFailed(now.Add(2*time.Second), "")
	if err != nil {
		t.Fatalf("mark totp failed: %v", err)
	}

	user, ok := factors.GetUserFactor()
	if !ok || !user.Verified() || user.AccountID != accountID {
		t.Fatalf("user factor = %#v, ok=%v", user, ok)
	}
	password, ok := factors.GetPasswordFactor()
	if !ok || !password.Verified() || password.ChallengeBinding != "password-check" {
		t.Fatalf("password factor = %#v, ok=%v", password, ok)
	}
	totp, ok := factors.GetTOTPFactor()
	if !ok || !totp.Failed() || totp.Verified() {
		t.Fatalf("totp factor = %#v, ok=%v", totp, ok)
	}

	if got, want := factors.VerifiedKinds(), []account.FactorKind{account.FactorKindUser, account.FactorKindPassword}; !reflect.DeepEqual(got, want) {
		t.Fatalf("verified kinds = %#v, want %#v", got, want)
	}
}

func TestSessionFactorsReplaceLatestState(t *testing.T) {
	now := time.Date(2026, 5, 3, 13, 15, 0, 0, time.UTC)
	factors := SessionFactors{}

	failed, err := factors.MarkRecoveryCodeFailed(now, "")
	if err != nil {
		t.Fatalf("mark recovery code failed: %v", err)
	}
	verified, err := failed.MarkRecoveryCodeVerified(now.Add(time.Second), "recovery-code-check")
	if err != nil {
		t.Fatalf("mark recovery code verified: %v", err)
	}

	if len(failed) != 1 || len(verified) != 1 {
		t.Fatalf("factor lengths failed=%d verified=%d", len(failed), len(verified))
	}
	if !failed[0].Failed() || failed[0].Verified() {
		t.Fatalf("failed factor state = %#v", failed[0])
	}
	if verified[0].Failed() || !verified[0].Verified() || verified[0].ChallengeBinding != "recovery-code-check" {
		t.Fatalf("verified factor state = %#v", verified[0])
	}
	if failed[0].ChallengeBinding == verified[0].ChallengeBinding {
		t.Fatal("marking a factor must not mutate the prior slice")
	}
}

func TestNormalizeFactorKindsDropsInvalidAndDuplicates(t *testing.T) {
	got := NormalizeFactorKinds([]account.FactorKind{
		account.FactorKindUser,
		account.FactorKind(""),
		account.FactorKindPassword,
		account.FactorKindUser,
		account.FactorKind("sms"),
		account.FactorKindTOTP,
	})
	want := []account.FactorKind{
		account.FactorKindUser,
		account.FactorKindPassword,
		account.FactorKindTOTP,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized factors = %#v, want %#v", got, want)
	}
}

func TestSessionFactorUpdatesValidateInput(t *testing.T) {
	if _, err := (SessionFactors{}).MarkVerified(FactorUpdate{Kind: account.FactorKind("sms"), CheckedAt: time.Now()}); err == nil {
		t.Fatal("invalid factor kind error = nil")
	}
	if _, err := (SessionFactors{}).MarkFailed(FactorUpdate{Kind: account.FactorKindTOTP}); err == nil {
		t.Fatal("missing check time error = nil")
	}
}
