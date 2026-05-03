// Package webauthntest provides a browserless WebAuthn client for tests.
package webauthntest

import (
	"fmt"

	"github.com/descope/virtualwebauthn"
)

// Client creates attestation and assertion responses for one virtual passkey.
type Client struct {
	relyingParty          virtualwebauthn.RelyingParty
	authenticator         virtualwebauthn.Authenticator
	verifiedAuthenticator virtualwebauthn.Authenticator
	credential            virtualwebauthn.Credential
}

// NewClient builds a virtual WebAuthn client for one relying party.
func NewClient(name, domain, origin string) *Client {
	return &Client{
		relyingParty: virtualwebauthn.RelyingParty{
			Name:   name,
			ID:     domain,
			Origin: origin,
		},
		authenticator: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
			UserNotVerified: true,
		}),
		verifiedAuthenticator: virtualwebauthn.NewAuthenticator(),
		credential:            virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
}

// SetUserHandle sets the user handle returned in assertion responses.
func (c *Client) SetUserHandle(userHandle []byte) {
	c.authenticator.Options.UserHandle = append([]byte(nil), userHandle...)
	c.verifiedAuthenticator.Options.UserHandle = append([]byte(nil), userHandle...)
}

// SetSignCount sets the authenticator sign counter used in assertion responses.
func (c *Client) SetSignCount(counter uint32) {
	c.credential.Counter = counter
}

// KeyID returns the virtual credential ID.
func (c *Client) KeyID() []byte {
	return append([]byte(nil), c.credential.ID...)
}

// CreateAttestationResponse returns a browser-style attestation response.
func (c *Client) CreateAttestationResponse(options []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("webauthntest: client is nil")
	}
	parsed, err := virtualwebauthn.ParseAttestationOptions(string(options))
	if err != nil {
		return nil, fmt.Errorf("webauthntest: parse attestation options: %w", err)
	}
	response := virtualwebauthn.CreateAttestationResponse(c.relyingParty, c.authenticator, c.credential, *parsed)
	return []byte(response), nil
}

// CreateAssertionResponse returns a browser-style assertion response.
func (c *Client) CreateAssertionResponse(options []byte, verifyUser bool) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("webauthntest: client is nil")
	}
	parsed, err := virtualwebauthn.ParseAssertionOptions(string(options))
	if err != nil {
		return nil, fmt.Errorf("webauthntest: parse assertion options: %w", err)
	}
	authenticator := c.authenticator
	if verifyUser {
		authenticator = c.verifiedAuthenticator
	}
	response := virtualwebauthn.CreateAssertionResponse(c.relyingParty, authenticator, c.credential, *parsed)
	return []byte(response), nil
}
