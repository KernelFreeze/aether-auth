package mfa

import (
	"context"
	"fmt"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

// PolicyReason explains why a login needs an extra factor.
type PolicyReason string

const (
	// PolicyReasonAccount means the account itself requires MFA.
	PolicyReasonAccount PolicyReason = "account"
	// PolicyReasonOrganization means the organization requires MFA.
	PolicyReasonOrganization PolicyReason = "organization"
)

// OrganizationPolicyChecker is the hook the organization feature can implement
// when organization-level MFA policy lands.
type OrganizationPolicyChecker interface {
	OrganizationMFARequired(context.Context, account.AccountID, account.OrganizationID) (bool, error)
}

// SessionIssuer is the full-session issue surface used after MFA is complete.
type SessionIssuer interface {
	IssueSession(context.Context, auth.SessionIssueRequest) (auth.SessionIssueResult, error)
}

// PolicyDeps holds collaborators and factor rules for PolicyService.
type PolicyDeps struct {
	OrganizationPolicies OrganizationPolicyChecker
	Sessions             SessionIssuer
	PrimaryFactors       []account.FactorKind
	SecondFactorOptions  []account.FactorKind
}

// PolicyService evaluates MFA requirements and guards partial-session upgrades.
type PolicyService struct {
	organizations       OrganizationPolicyChecker
	sessions            SessionIssuer
	primaryFactors      []account.FactorKind
	secondFactorOptions []account.FactorKind
}

// NewPolicyService builds the shared MFA policy service.
func NewPolicyService(deps PolicyDeps) *PolicyService {
	return &PolicyService{
		organizations:       deps.OrganizationPolicies,
		sessions:            deps.Sessions,
		primaryFactors:      factorsOrDefault(deps.PrimaryFactors, defaultPrimaryFactors()),
		secondFactorOptions: factorsOrDefault(deps.SecondFactorOptions, defaultSecondFactorOptions()),
	}
}

// PolicyRequest contains the account and factor state used to evaluate MFA.
type PolicyRequest struct {
	AccountID          account.AccountID
	OrganizationID     account.OrganizationID
	AccountMFAEnforced bool
	SessionFactors     SessionFactors
	VerifiedFactors    []account.FactorKind
}

// PolicyDecision is the result of applying account and organization MFA policy.
type PolicyDecision struct {
	Required            bool
	Satisfied           bool
	Status              auth.MFAStatus
	Reasons             []PolicyReason
	VerifiedFactors     []account.FactorKind
	PrimaryFactors      []account.FactorKind
	SecondFactorOptions []account.FactorKind
	MissingFactors      []account.FactorKind
}

// UpgradeRequest contains a partial session and the context for issuing a full
// session after MFA factors are complete.
type UpgradeRequest struct {
	PartialSession     auth.PartialSession
	OrganizationID     account.OrganizationID
	AccountMFAEnforced bool
	ClientID           account.ClientID
	Scopes             []string
	Audience           []string
	IP                 string
	UserAgent          string
	Now                time.Time
}

// UpgradeResult returns the policy decision and the issued full session.
type UpgradeResult struct {
	Policy  PolicyDecision
	Session auth.SessionIssueResult
}

// Evaluate derives the MFA requirement and checks whether the verified factors
// satisfy it.
func (s *PolicyService) Evaluate(ctx context.Context, req PolicyRequest) (PolicyDecision, error) {
	if req.AccountID.IsZero() {
		return PolicyDecision{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "mfa account id is required", nil)
	}

	verified := req.SessionFactors.VerifiedKinds()
	if len(verified) == 0 {
		verified = NormalizeFactorKinds(req.VerifiedFactors)
	}
	primary := s.primary()
	second := s.secondFactors()
	reasons := make([]PolicyReason, 0, 2)
	if req.AccountMFAEnforced {
		reasons = append(reasons, PolicyReasonAccount)
	}

	if !req.OrganizationID.IsZero() && s != nil && s.organizations != nil {
		required, err := s.organizations.OrganizationMFARequired(ctx, req.AccountID, req.OrganizationID)
		if err != nil {
			return PolicyDecision{}, fmt.Errorf("mfa: check organization policy: %w", err)
		}
		if required {
			reasons = append(reasons, PolicyReasonOrganization)
		}
	}

	required := len(reasons) > 0
	var missing []account.FactorKind
	if required {
		missing = missingPrimaryFactors(primary, verified)
		if !hasAnyFactor(verified, second) {
			missing = append(missing, second...)
		}
	}
	satisfied := !required || len(missing) == 0
	status := auth.MFAStatusNotRequired
	if required {
		status = auth.MFAStatusRequired
		if satisfied {
			status = auth.MFAStatusSatisfied
		}
	}

	return PolicyDecision{
		Required:            required,
		Satisfied:           satisfied,
		Status:              status,
		Reasons:             append([]PolicyReason(nil), reasons...),
		VerifiedFactors:     verified,
		PrimaryFactors:      primary,
		SecondFactorOptions: second,
		MissingFactors:      missing,
	}, nil
}

// Upgrade issues a full session only when the partial-session factors satisfy
// the current MFA policy.
func (s *PolicyService) Upgrade(ctx context.Context, req UpgradeRequest) (UpgradeResult, error) {
	if s == nil {
		return UpgradeResult{}, auth.NewServiceError(auth.ErrorKindInternal, "mfa policy service is nil", nil)
	}
	if s.sessions == nil {
		return UpgradeResult{}, auth.NewServiceError(auth.ErrorKindInternal, "mfa session issuer is nil", nil)
	}
	if req.PartialSession.ID.IsZero() || req.PartialSession.AccountID.IsZero() {
		return UpgradeResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "partial session is required", nil)
	}

	now := normalizeTime(req.Now)
	if account.IsExpired(now, req.PartialSession.ExpiresAt) {
		return UpgradeResult{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "partial session is expired", nil)
	}

	decision, err := s.Evaluate(ctx, PolicyRequest{
		AccountID:          req.PartialSession.AccountID,
		OrganizationID:     req.OrganizationID,
		AccountMFAEnforced: req.AccountMFAEnforced,
		VerifiedFactors:    req.PartialSession.VerifiedFactors,
	})
	if err != nil {
		return UpgradeResult{}, err
	}
	if !decision.Satisfied {
		return UpgradeResult{Policy: decision}, auth.NewServiceError(auth.ErrorKindPolicyDenied, "mfa requirements are not satisfied", nil)
	}

	session, err := s.sessions.IssueSession(ctx, auth.SessionIssueRequest{
		AccountID:       req.PartialSession.AccountID,
		ClientID:        req.ClientID,
		VerifiedFactors: decision.VerifiedFactors,
		Scopes:          append([]string(nil), req.Scopes...),
		Audience:        append([]string(nil), req.Audience...),
		IP:              req.IP,
		UserAgent:       req.UserAgent,
		Now:             now,
	})
	if err != nil {
		return UpgradeResult{}, err
	}

	return UpgradeResult{Policy: decision, Session: session}, nil
}

func (s *PolicyService) primary() []account.FactorKind {
	if s == nil {
		return defaultPrimaryFactors()
	}
	return factorsOrDefault(s.primaryFactors, defaultPrimaryFactors())
}

func (s *PolicyService) secondFactors() []account.FactorKind {
	if s == nil {
		return defaultSecondFactorOptions()
	}
	return factorsOrDefault(s.secondFactorOptions, defaultSecondFactorOptions())
}

func defaultPrimaryFactors() []account.FactorKind {
	return []account.FactorKind{account.FactorKindUser, account.FactorKindPassword}
}

func defaultSecondFactorOptions() []account.FactorKind {
	return []account.FactorKind{
		account.FactorKindTOTP,
		account.FactorKindRecoveryCode,
		account.FactorKindPasskey,
	}
}

func factorsOrDefault(values, defaults []account.FactorKind) []account.FactorKind {
	normalized := NormalizeFactorKinds(values)
	if len(normalized) == 0 {
		return append([]account.FactorKind(nil), defaults...)
	}
	return normalized
}

func missingPrimaryFactors(required, verified []account.FactorKind) []account.FactorKind {
	missing := make([]account.FactorKind, 0, len(required))
	for _, factor := range required {
		if !hasFactor(verified, factor) {
			missing = append(missing, factor)
		}
	}
	return missing
}

func hasAnyFactor(verified, allowed []account.FactorKind) bool {
	for _, factor := range allowed {
		if hasFactor(verified, factor) {
			return true
		}
	}
	return false
}

func hasFactor(values []account.FactorKind, target account.FactorKind) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func normalizeTime(t time.Time) time.Time {
	if t.IsZero() {
		return account.NormalizeTimestamp(time.Now())
	}
	return account.NormalizeTimestamp(t)
}
