package mfa

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/auth/totp"
	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the MFA feature.
type Deps struct {
	Policy          *PolicyService
	PartialSessions auth.PartialSessionVerifier
	Accounts        AccountStateReader
	TOTP            TOTPVerifier
}

// Module owns MFA policy and challenge HTTP handlers.
type Module struct {
	policy          *PolicyService
	partialSessions auth.PartialSessionVerifier
	accounts        AccountStateReader
	totp            TOTPVerifier
}

var _ httpapi.Module = (*Module)(nil)

// AccountStateReader loads account security state before issuing a full session.
type AccountStateReader interface {
	AccountState(context.Context, account.AccountID) (auth.AccountState, error)
}

// TOTPVerifier checks TOTP and recovery-code second factors.
type TOTPVerifier interface {
	VerifyTOTP(context.Context, totp.VerifyTOTPRequest) (auth.FactorCheck, auth.CredentialSnapshot, error)
	VerifyRecoveryCode(context.Context, totp.VerifyRecoveryCodeRequest) (auth.FactorCheck, auth.CredentialSnapshot, error)
}

// New builds the MFA feature module.
func New(deps Deps) *Module {
	return &Module{
		policy:          deps.Policy,
		partialSessions: deps.PartialSessions,
		accounts:        deps.Accounts,
		totp:            deps.TOTP,
	}
}

// RegisterRoutes mounts MFA routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(r gin.IRouter, _ httpapi.Middlewares) {
	r.POST("/verify", m.handleVerify)
}
