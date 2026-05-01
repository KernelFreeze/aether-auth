package keys

import (
	"encoding/base64"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
)

const (
	// PASETOVersion identifies the public-token protocol resource servers can
	// verify with this endpoint.
	PASETOVersion = "v4.public"
)

// Source exposes active and retained PASETO public verification keys.
type Source interface {
	PublicKeys() []paseto.PublicKey
}

// Document is the public key discovery response returned from
// /.well-known/paseto-keys.
type Document struct {
	Keys []VerificationKey `json:"keys"`
}

// VerificationKey is the JWKS-shaped representation of a PASETO v4.public
// Ed25519 verification key.
type VerificationKey struct {
	KeyID         string     `json:"kid"`
	KeyType       string     `json:"kty"`
	Curve         string     `json:"crv"`
	Algorithm     string     `json:"alg"`
	Use           string     `json:"use"`
	X             string     `json:"x"`
	PASETOVersion string     `json:"paseto_version"`
	Status        string     `json:"status"`
	RetainUntil   *time.Time `json:"retain_until,omitempty"`
}

// DiscoveryDocument converts keystore keys into the public discovery format.
func DiscoveryDocument(source Source) Document {
	if source == nil {
		return Document{Keys: []VerificationKey{}}
	}
	return DocumentFromKeys(source.PublicKeys())
}

// DocumentFromKeys converts raw Ed25519 public keys into a stable JSON shape.
func DocumentFromKeys(publicKeys []paseto.PublicKey) Document {
	keys := make([]VerificationKey, 0, len(publicKeys))
	for _, key := range publicKeys {
		status := "retained"
		if key.Active {
			status = "active"
		}

		var retainUntil *time.Time
		if !key.RetainUntil.IsZero() {
			t := key.RetainUntil.UTC()
			retainUntil = &t
		}

		keys = append(keys, VerificationKey{
			KeyID:         key.KeyID,
			KeyType:       "OKP",
			Curve:         "Ed25519",
			Algorithm:     "EdDSA",
			Use:           "sig",
			X:             base64.RawURLEncoding.EncodeToString(key.Key),
			PASETOVersion: PASETOVersion,
			Status:        status,
			RetainUntil:   retainUntil,
		})
	}
	return Document{Keys: keys}
}
