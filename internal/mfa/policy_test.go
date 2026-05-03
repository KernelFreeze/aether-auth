package mfa

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

func TestPolicyServiceEvaluateDerivesAccountRequirement(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000901")
	service := NewPolicyService(PolicyDeps{})

	decision, err := service.Evaluate(context.Background(), PolicyRequest{
		AccountID:          accountID,
		AccountMFAEnforced: true,
		VerifiedFactors: []account.FactorKind{
			account.FactorKindUser,
			account.FactorKindPassword,
			account.FactorKindTOTP,
		},
	})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}

	if !decision.Required || !decision.Satisfied || decision.Status != auth.MFAStatusSatisfied {
		t.Fatalf("decision = %#v", decision)
	}
	if !reflect.DeepEqual(decision.Reasons, []PolicyReason{PolicyReasonAccount}) {
		t.Fatalf("reasons = %#v", decision.Reasons)
	}
	if !reflect.DeepEqual(decision.SecondFactorOptions, []account.FactorKind{
		account.FactorKindTOTP,
		account.FactorKindRecoveryCode,
		account.FactorKindPasskey,
	}) {
		t.Fatalf("second factor options = %#v", decision.SecondFactorOptions)
	}
}

func TestPolicyServiceEvaluateUsesOrganizationHook(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000902")
	orgID := mustOrganizationID(t, "018f1f74-10a1-7000-9000-000000000903")
	orgs := &organizationPolicies{required: true}
	service := NewPolicyService(PolicyDeps{OrganizationPolicies: orgs})

	decision, err := service.Evaluate(context.Background(), PolicyRequest{
		AccountID:      accountID,
		OrganizationID: orgID,
		VerifiedFactors: []account.FactorKind{
			account.FactorKindUser,
			account.FactorKindPassword,
			account.FactorKindRecoveryCode,
		},
	})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}

	if orgs.accountID != accountID || orgs.organizationID != orgID {
		t.Fatalf("organization hook inputs = account %s organization %s", orgs.accountID, orgs.organizationID)
	}
	if !decision.Required || !decision.Satisfied || !reflect.DeepEqual(decision.Reasons, []PolicyReason{PolicyReasonOrganization}) {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestPolicyServiceEvaluateReportsMissingFactors(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000904")
	service := NewPolicyService(PolicyDeps{})

	decision, err := service.Evaluate(context.Background(), PolicyRequest{
		AccountID:          accountID,
		AccountMFAEnforced: true,
		VerifiedFactors: []account.FactorKind{
			account.FactorKindUser,
			account.FactorKindPassword,
		},
	})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}

	if !decision.Required || decision.Satisfied || decision.Status != auth.MFAStatusRequired {
		t.Fatalf("decision = %#v", decision)
	}
	if !reflect.DeepEqual(decision.MissingFactors, []account.FactorKind{
		account.FactorKindTOTP,
		account.FactorKindRecoveryCode,
		account.FactorKindPasskey,
	}) {
		t.Fatalf("missing factors = %#v", decision.MissingFactors)
	}

	decision, err = service.Evaluate(context.Background(), PolicyRequest{
		AccountID:          accountID,
		AccountMFAEnforced: true,
		VerifiedFactors:    []account.FactorKind{account.FactorKindTOTP},
	})
	if err != nil {
		t.Fatalf("evaluate missing primary policy: %v", err)
	}
	if !reflect.DeepEqual(decision.MissingFactors, []account.FactorKind{
		account.FactorKindUser,
		account.FactorKindPassword,
	}) {
		t.Fatalf("missing primary factors = %#v", decision.MissingFactors)
	}
}

func TestPolicyServiceEvaluateNoRequirementIsSatisfied(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000905")
	service := NewPolicyService(PolicyDeps{})

	decision, err := service.Evaluate(context.Background(), PolicyRequest{AccountID: accountID})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if decision.Required || !decision.Satisfied || decision.Status != auth.MFAStatusNotRequired || len(decision.MissingFactors) != 0 {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestPolicyServiceUpgradeIssuesSessionAfterMFA(t *testing.T) {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000906")
	partialID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000907")
	fullID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000908")
	sessions := &sessionIssuer{result: auth.SessionIssueResult{
		SessionID:    fullID,
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    now.Add(15 * time.Minute),
	}}
	service := NewPolicyService(PolicyDeps{Sessions: sessions})

	result, err := service.Upgrade(context.Background(), UpgradeRequest{
		PartialSession: auth.PartialSession{
			ID:        partialID,
			AccountID: accountID,
			VerifiedFactors: []account.FactorKind{
				account.FactorKindUser,
				account.FactorKindPassword,
				account.FactorKindTOTP,
			},
			ExpiresAt: now.Add(time.Minute),
		},
		AccountMFAEnforced: true,
		Scopes:             []string{"openid", "profile"},
		Audience:           []string{"https://api.example.test"},
		IP:                 "203.0.113.10",
		UserAgent:          "mfa-test",
		Now:                now,
	})
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}

	if result.Session.SessionID != fullID || !result.Policy.Satisfied {
		t.Fatalf("upgrade result = %#v", result)
	}
	if sessions.req.AccountID != accountID || sessions.req.IP != "203.0.113.10" || sessions.req.UserAgent != "mfa-test" || !sessions.req.Now.Equal(now) {
		t.Fatalf("session request = %#v", sessions.req)
	}
	if !reflect.DeepEqual(sessions.req.VerifiedFactors, []account.FactorKind{
		account.FactorKindUser,
		account.FactorKindPassword,
		account.FactorKindTOTP,
	}) {
		t.Fatalf("session factors = %#v", sessions.req.VerifiedFactors)
	}
}

func TestPolicyServiceUpgradeRejectsUnsatisfiedOrExpiredPartialSession(t *testing.T) {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000909")
	partialID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000910")

	tests := []struct {
		name    string
		partial auth.PartialSession
		wantErr error
	}{
		{
			name: "missing second factor",
			partial: auth.PartialSession{
				ID:              partialID,
				AccountID:       accountID,
				VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword},
				ExpiresAt:       now.Add(time.Minute),
			},
			wantErr: auth.ErrPolicyDenied,
		},
		{
			name: "expired partial session",
			partial: auth.PartialSession{
				ID:              partialID,
				AccountID:       accountID,
				VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword, account.FactorKindTOTP},
				ExpiresAt:       now,
			},
			wantErr: auth.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions := &sessionIssuer{}
			service := NewPolicyService(PolicyDeps{Sessions: sessions})
			_, err := service.Upgrade(context.Background(), UpgradeRequest{
				PartialSession:     tt.partial,
				AccountMFAEnforced: true,
				Now:                now,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("upgrade error = %v, want %v", err, tt.wantErr)
			}
			if sessions.called {
				t.Fatal("full session should not be issued")
			}
		})
	}
}

type organizationPolicies struct {
	required       bool
	err            error
	accountID      account.AccountID
	organizationID account.OrganizationID
}

func (p *organizationPolicies) OrganizationMFARequired(_ context.Context, accountID account.AccountID, organizationID account.OrganizationID) (bool, error) {
	p.accountID = accountID
	p.organizationID = organizationID
	return p.required, p.err
}

type sessionIssuer struct {
	called bool
	req    auth.SessionIssueRequest
	result auth.SessionIssueResult
	err    error
}

func (s *sessionIssuer) IssueSession(_ context.Context, req auth.SessionIssueRequest) (auth.SessionIssueResult, error) {
	s.called = true
	s.req = req
	return s.result, s.err
}

func mustAccountID(t *testing.T, value string) account.AccountID {
	t.Helper()
	id := uuid.MustParse(value)
	return account.AccountID(id)
}

func mustSessionID(t *testing.T, value string) account.SessionID {
	t.Helper()
	id := uuid.MustParse(value)
	return account.SessionID(id)
}

func mustOrganizationID(t *testing.T, value string) account.OrganizationID {
	t.Helper()
	id := uuid.MustParse(value)
	return account.OrganizationID(id)
}
