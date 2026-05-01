package auth

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

func TestAuthMethodContractSupportsImmediateAndChallengeMethods(t *testing.T) {
	accountID, credentialID := mustAuthIDs(t)
	ip := netip.MustParseAddr("203.0.113.10")

	methods := []AuthMethod{
		fakeAuthMethod{
			kind: account.CredentialKindPassword,
			begin: func(context.Context, BeginRequest) (BeginResult, error) {
				return BeginResult{}, nil
			},
			verify: func(_ context.Context, req VerifyRequest) (AuthResult, error) {
				if req.ChallengeID != "" {
					t.Fatalf("password challenge ID = %q, want empty", req.ChallengeID)
				}
				return AuthResult{
					AccountID:       accountID,
					CredentialID:    credentialID,
					VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword},
					MFAStatus:       MFAStatusNotRequired,
					Audit: AuditMetadata{
						EventType: "auth.password.verified",
						RequestID: req.RequestID,
						IP:        req.IP,
						UserAgent: req.UserAgent,
					},
					Session: SessionIssueInstructions{
						Issue:     true,
						ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
						Scopes:    []string{"profile:read"},
					},
				}, nil
			},
		},
		fakeAuthMethod{
			kind: account.CredentialKindWebAuthn,
			begin: func(_ context.Context, req BeginRequest) (BeginResult, error) {
				if req.Username != "celeste" {
					t.Fatalf("username = %q, want celeste", req.Username)
				}
				return BeginResult{
					ChallengePayload: map[string]any{"publicKey": "challenge"},
					ChallengeID:      "challenge-123",
					ExpiresAt:        time.Now().UTC().Add(time.Minute),
					PublicMetadata:   map[string]string{"kind": account.CredentialKindWebAuthn.String()},
				}, nil
			},
			verify: func(_ context.Context, req VerifyRequest) (AuthResult, error) {
				if req.ChallengeID != "challenge-123" {
					t.Fatalf("challenge ID = %q, want challenge-123", req.ChallengeID)
				}
				return AuthResult{
					AccountID:       accountID,
					CredentialID:    credentialID,
					VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPasskey},
					MFAStatus:       MFAStatusSatisfied,
					Audit: AuditMetadata{
						EventType: "auth.webauthn.verified",
						RequestID: req.RequestID,
						IP:        req.IP,
						UserAgent: req.UserAgent,
					},
					Session: SessionIssueInstructions{Issue: true},
				}, nil
			},
		},
	}

	for _, method := range methods {
		t.Run(method.Kind().String(), func(t *testing.T) {
			begin, err := method.Begin(context.Background(), BeginRequest{
				Username:  "celeste",
				IP:        ip,
				UserAgent: "Mozilla/5.0",
				RequestID: "req-123",
			})
			if err != nil {
				t.Fatalf("begin: %v", err)
			}

			result, err := method.Verify(context.Background(), VerifyRequest{
				CredentialInput: "secret",
				ChallengeID:     begin.ChallengeID,
				AccountHint:     accountID,
				IP:              ip,
				UserAgent:       "Mozilla/5.0",
				RequestID:       "req-123",
			})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if result.AccountID != accountID {
				t.Fatalf("account ID = %v, want %v", result.AccountID, accountID)
			}
			if result.CredentialID != credentialID {
				t.Fatalf("credential ID = %v, want %v", result.CredentialID, credentialID)
			}
			if len(result.VerifiedFactors) == 0 {
				t.Fatal("verified factors should not be empty")
			}
			if !result.Session.Issue {
				t.Fatal("verified method should request session issuance")
			}
		})
	}
}

func TestAuthContractCloneDetachesMutableFields(t *testing.T) {
	accountID, credentialID := mustAuthIDs(t)
	external := &ExternalIdentity{
		Provider: "google",
		Subject:  "sub-123",
		Metadata: map[string]string{"hd": "example.com"},
	}
	result := AuthResult{
		AccountID:        accountID,
		CredentialID:     credentialID,
		VerifiedFactors:  []account.FactorKind{account.FactorKindUser},
		ExternalIdentity: external,
		Audit: AuditMetadata{
			Attributes: map[string]string{"risk": "low"},
		},
		Session: SessionIssueInstructions{
			Scopes:   []string{"profile:read"},
			Audience: []string{"api"},
		},
		PublicMetadata: map[string]string{"next": "mfa"},
	}

	cloned := result.Clone()
	result.VerifiedFactors[0] = account.FactorKindPassword
	result.ExternalIdentity.Metadata["hd"] = "mutated.example"
	result.Audit.Attributes["risk"] = "high"
	result.Session.Scopes[0] = "mutated"
	result.Session.Audience[0] = "mutated"
	result.PublicMetadata["next"] = "done"

	if cloned.VerifiedFactors[0] != account.FactorKindUser {
		t.Fatalf("cloned factor = %q, want %q", cloned.VerifiedFactors[0], account.FactorKindUser)
	}
	if cloned.ExternalIdentity.Metadata["hd"] != "example.com" {
		t.Fatalf("cloned external metadata = %q, want example.com", cloned.ExternalIdentity.Metadata["hd"])
	}
	if cloned.Audit.Attributes["risk"] != "low" {
		t.Fatalf("cloned audit risk = %q, want low", cloned.Audit.Attributes["risk"])
	}
	if cloned.Session.Scopes[0] != "profile:read" {
		t.Fatalf("cloned scope = %q, want profile:read", cloned.Session.Scopes[0])
	}
	if cloned.Session.Audience[0] != "api" {
		t.Fatalf("cloned audience = %q, want api", cloned.Session.Audience[0])
	}
	if cloned.PublicMetadata["next"] != "mfa" {
		t.Fatalf("cloned metadata next = %q, want mfa", cloned.PublicMetadata["next"])
	}
}

type fakeAuthMethod struct {
	kind   account.CredentialKind
	begin  func(context.Context, BeginRequest) (BeginResult, error)
	verify func(context.Context, VerifyRequest) (AuthResult, error)
}

func (m fakeAuthMethod) Kind() account.CredentialKind {
	return m.kind
}

func (m fakeAuthMethod) Begin(ctx context.Context, req BeginRequest) (BeginResult, error) {
	return m.begin(ctx, req)
}

func (m fakeAuthMethod) Verify(ctx context.Context, req VerifyRequest) (AuthResult, error) {
	return m.verify(ctx, req)
}

func mustAuthIDs(t *testing.T) (account.AccountID, account.CredentialID) {
	t.Helper()

	accountID, err := account.ParseAccountID("018f1f47-4000-7c09-8d93-9f12a5e0a111")
	if err != nil {
		t.Fatalf("parse account ID: %v", err)
	}
	credentialID, err := account.ParseCredentialID("018f1f47-4000-7c09-8d93-9f12a5e0a222")
	if err != nil {
		t.Fatalf("parse credential ID: %v", err)
	}
	return accountID, credentialID
}
