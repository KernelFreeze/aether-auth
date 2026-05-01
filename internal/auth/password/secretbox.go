package password

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/KernelFreeze/aether-auth/internal/auth"
	platformcrypto "github.com/KernelFreeze/aether-auth/internal/platform/crypto"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
)

const aes256KeySize = 32

// AESGCMBox encrypts password credential payloads with AES-256-GCM.
type AESGCMBox struct {
	key    []byte
	keyID  string
	random io.Reader
}

var _ auth.SecretBox = (*AESGCMBox)(nil)

// NewAESGCMBox resolves keyRef and builds an AES-256-GCM credential box.
func NewAESGCMBox(ctx context.Context, sec secrets.Provider, keyRef string, random io.Reader) (*AESGCMBox, error) {
	if sec == nil {
		return nil, auth.NewServiceError(auth.ErrorKindInternal, "secret provider is nil", nil)
	}
	raw, err := sec.Resolve(ctx, keyRef)
	if err != nil {
		return nil, err
	}
	key, ok := decodeKeyMaterial(raw, aes256KeySize)
	if !ok {
		return nil, fmt.Errorf("%w: %s must resolve to 32 bytes", platformcrypto.ErrInvalidAESKey, keyRef)
	}
	return &AESGCMBox{
		key:    key,
		keyID:  keyID(key),
		random: random,
	}, nil
}

// Seal encrypts plaintext with associated data.
func (b *AESGCMBox) Seal(_ context.Context, req auth.SecretBoxSealRequest) (auth.SecretBoxPayload, error) {
	if b == nil || len(b.key) == 0 {
		return auth.SecretBoxPayload{}, auth.NewServiceError(auth.ErrorKindInternal, "aes-gcm box is nil", nil)
	}
	ciphertext, err := platformcrypto.SealCredentialPayload(b.key, req.Plaintext, req.AssociatedData, b.randomReader())
	if err != nil {
		return auth.SecretBoxPayload{}, err
	}
	return auth.SecretBoxPayload{
		KeyID:      b.keyID,
		Ciphertext: ciphertext,
	}, nil
}

// Open decrypts a payload created by Seal.
func (b *AESGCMBox) Open(_ context.Context, req auth.SecretBoxOpenRequest) ([]byte, error) {
	if b == nil || len(b.key) == 0 {
		return nil, auth.NewServiceError(auth.ErrorKindInternal, "aes-gcm box is nil", nil)
	}
	if req.Payload.KeyID != "" && req.Payload.KeyID != b.keyID {
		return nil, platformcrypto.ErrInvalidCiphertext
	}
	return platformcrypto.OpenCredentialPayload(b.key, req.Payload.Ciphertext, req.AssociatedData)
}

func (b *AESGCMBox) randomReader() io.Reader {
	if b.random != nil {
		return b.random
	}
	return rand.Reader
}

func decodeKeyMaterial(raw []byte, size int) ([]byte, bool) {
	if len(raw) == size {
		return append([]byte(nil), raw...), true
	}
	text := strings.TrimSpace(string(raw))
	if len(text) == size {
		return []byte(text), true
	}
	for _, decode := range []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		decoded, err := decode(text)
		if err == nil && len(decoded) == size {
			return decoded, true
		}
	}
	return nil, false
}

func keyID(material []byte) string {
	sum := sha256.Sum256(material)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
