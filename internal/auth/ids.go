package auth

import (
	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

// UUIDGenerator creates UUIDv7 identifiers for auth collaborators.
type UUIDGenerator struct{}

var _ IDGenerator = UUIDGenerator{}

func (UUIDGenerator) NewAccountID() (account.AccountID, error) {
	return account.NewAccountID()
}

func (UUIDGenerator) NewCredentialID() (account.CredentialID, error) {
	return account.NewCredentialID()
}

func (UUIDGenerator) NewSessionID() (account.SessionID, error) {
	return account.NewSessionID()
}

func (UUIDGenerator) NewOrganizationID() (account.OrganizationID, error) {
	return account.NewOrganizationID()
}

func (UUIDGenerator) NewClientID() (account.ClientID, error) {
	return account.NewClientID()
}

func (UUIDGenerator) NewChallengeID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
