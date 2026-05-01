package paseto

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	gopaseto "aidanwoods.dev/go-paseto"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
)

var (
	// ErrInvalidKeyMaterial means a secret reference resolved but did not
	// contain usable PASETO key bytes.
	ErrInvalidKeyMaterial = errors.New("paseto: invalid key material")
	// ErrInvalidFooter means a token footer is missing the key ID or is not
	// valid JSON.
	ErrInvalidFooter = errors.New("paseto: invalid footer")
	// ErrKeystoreNotLoaded means token operations were called before key
	// material was loaded.
	ErrKeystoreNotLoaded = errors.New("paseto: keystore not loaded")
	// ErrUnknownKeyID means the token footer references a key this keystore
	// does not know how to verify.
	ErrUnknownKeyID = errors.New("paseto: unknown key id")
)

// Rule is a PASETO claim validation rule.
type Rule = gopaseto.Rule

// Token is a verified or decrypted PASETO token.
type Token = gopaseto.Token

// Keystore exposes the active PASETO signing/encryption keys and the older
// verification keys retained during a rotation overlap window.
type Keystore struct {
	mu  sync.RWMutex
	cfg config.PASETOConfig
	sec secrets.Provider

	refs Refs

	signing      signingKey
	local        localKey
	verification map[string]publicKey
}

// NewKeystore loads the active v4.public and v4.local keys from secret refs.
func NewKeystore(ctx context.Context, cfg config.PASETOConfig, sec secrets.Provider, refs Refs) (*Keystore, error) {
	k := &Keystore{
		cfg:          cfg,
		sec:          sec,
		refs:         refs,
		verification: make(map[string]publicKey),
	}
	if err := k.Reload(ctx); err != nil {
		return nil, err
	}
	return k, nil
}

// Refs collects the secret URI references the keystore needs at boot.
type Refs struct {
	LocalKey   string
	PublicSeed string
}

// PublicKey is the active or retained v4.public verification key. The key is
// raw Ed25519 public-key bytes.
type PublicKey struct {
	KeyID string
	Key   []byte
}

// IssueRequest contains claims and implicit assertion data for a new token.
type IssueRequest struct {
	Claims   map[string]any
	Implicit []byte
}

// Reload re-reads the active keys from the secrets provider. Existing public
// verification keys are retained so access tokens issued before a rotation can
// be verified during the configured overlap window.
func (k *Keystore) Reload(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	local, err := k.loadLocalKey(ctx)
	if err != nil {
		return err
	}
	signing, err := k.loadSigningKey(ctx)
	if err != nil {
		return err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	verification := make(map[string]publicKey, len(k.verification)+1)
	for kid, key := range k.verification {
		verification[kid] = key
	}
	verification[signing.KeyID] = signing.publicKey

	k.local = local
	k.signing = signing
	k.verification = verification
	return nil
}

// PublicKeys returns public verification keys known to the keystore.
func (k *Keystore) PublicKeys() []PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()

	keys := make([]PublicKey, 0, len(k.verification))
	for _, key := range k.verification {
		keys = append(keys, PublicKey{
			KeyID: key.KeyID,
			Key:   append([]byte(nil), key.Bytes...),
		})
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].KeyID < keys[j].KeyID
	})
	return keys
}

// IssueAccessToken signs claims as a PASETO v4.public token. The footer carries
// the active signing key ID.
func (k *Keystore) IssueAccessToken(ctx context.Context, req IssueRequest) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	k.mu.RLock()
	signing := k.signing
	k.mu.RUnlock()
	if signing.KeyID == "" {
		return "", ErrKeystoreNotLoaded
	}

	token, err := tokenFromClaims(req.Claims, signing.KeyID)
	if err != nil {
		return "", err
	}
	return token.V4Sign(signing.Secret, req.Implicit), nil
}

// VerifyAccessToken verifies a PASETO v4.public token using the key selected
// from the token footer's kid value.
func (k *Keystore) VerifyAccessToken(ctx context.Context, raw string, implicit []byte, rules ...Rule) (*Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	footer, err := unsafeFooter(gopaseto.V4Public, raw)
	if err != nil {
		return nil, err
	}

	k.mu.RLock()
	key, ok := k.verification[footer.KeyID]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, footer.KeyID)
	}

	parser := parserWithRules(rules)
	return parser.ParseV4Public(key.Key, raw, implicit)
}

// IssuePartialSessionToken encrypts claims as a PASETO v4.local token. The
// footer carries the active local key ID.
func (k *Keystore) IssuePartialSessionToken(ctx context.Context, req IssueRequest) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	k.mu.RLock()
	local := k.local
	k.mu.RUnlock()
	if local.KeyID == "" {
		return "", ErrKeystoreNotLoaded
	}

	token, err := tokenFromClaims(req.Claims, local.KeyID)
	if err != nil {
		return "", err
	}
	return token.V4Encrypt(local.Key, req.Implicit), nil
}

// VerifyPartialSessionToken decrypts a PASETO v4.local partial-session token.
func (k *Keystore) VerifyPartialSessionToken(ctx context.Context, raw string, implicit []byte, rules ...Rule) (*Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	footer, err := unsafeFooter(gopaseto.V4Local, raw)
	if err != nil {
		return nil, err
	}

	k.mu.RLock()
	local := k.local
	k.mu.RUnlock()
	if local.KeyID == "" {
		return nil, ErrKeystoreNotLoaded
	}
	if footer.KeyID != local.KeyID {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, footer.KeyID)
	}

	parser := parserWithRules(rules)
	return parser.ParseV4Local(local.Key, raw, implicit)
}

func (k *Keystore) loadLocalKey(ctx context.Context) (localKey, error) {
	material, err := k.resolveKeyBytes(ctx, k.refs.LocalKey, 32)
	if err != nil {
		return localKey{}, err
	}
	key, err := gopaseto.V4SymmetricKeyFromBytes(material)
	if err != nil {
		return localKey{}, fmt.Errorf("%w: %s", ErrInvalidKeyMaterial, k.refs.LocalKey)
	}
	return localKey{
		KeyID: keyID(material),
		Key:   key,
	}, nil
}

func (k *Keystore) loadSigningKey(ctx context.Context) (signingKey, error) {
	seed, err := k.resolveKeyBytes(ctx, k.refs.PublicSeed, ed25519.SeedSize)
	if err != nil {
		return signingKey{}, err
	}

	private := ed25519.NewKeyFromSeed(seed)
	secret, err := gopaseto.NewV4AsymmetricSecretKeyFromBytes(private)
	if err != nil {
		return signingKey{}, fmt.Errorf("%w: %s", ErrInvalidKeyMaterial, k.refs.PublicSeed)
	}
	public := secret.Public()
	publicBytes := public.ExportBytes()
	return signingKey{
		publicKey: publicKey{
			KeyID: keyID(publicBytes),
			Key:   public,
			Bytes: append([]byte(nil), publicBytes...),
		},
		Secret: secret,
	}, nil
}

func (k *Keystore) resolveKeyBytes(ctx context.Context, ref string, size int) ([]byte, error) {
	raw, err := k.sec.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	material, ok := decodeKeyMaterial(raw, size)
	if !ok {
		return nil, fmt.Errorf("%w: %s must resolve to %d bytes", ErrInvalidKeyMaterial, ref, size)
	}
	return material, nil
}

func decodeKeyMaterial(raw []byte, size int) ([]byte, bool) {
	if len(raw) == size {
		return append([]byte(nil), raw...), true
	}

	trimmed := []byte(strings.TrimSpace(string(raw)))
	if len(trimmed) == size {
		return append([]byte(nil), trimmed...), true
	}

	text := string(trimmed)
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

func tokenFromClaims(claims map[string]any, kid string) (gopaseto.Token, error) {
	token := gopaseto.NewToken()
	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			return gopaseto.Token{}, err
		}
	}
	footer, err := json.Marshal(tokenFooter{KeyID: kid})
	if err != nil {
		return gopaseto.Token{}, err
	}
	token.SetFooter(footer)
	return token, nil
}

func unsafeFooter(protocol gopaseto.Protocol, raw string) (tokenFooter, error) {
	footerBytes, err := gopaseto.NewParserWithoutExpiryCheck().UnsafeParseFooter(protocol, raw)
	if err != nil {
		return tokenFooter{}, err
	}

	var footer tokenFooter
	if err := json.Unmarshal(footerBytes, &footer); err != nil {
		return tokenFooter{}, fmt.Errorf("%w: %v", ErrInvalidFooter, err)
	}
	if footer.KeyID == "" {
		return tokenFooter{}, ErrInvalidFooter
	}
	return footer, nil
}

func parserWithRules(rules []Rule) gopaseto.Parser {
	parser := gopaseto.NewParser()
	if len(rules) > 0 {
		parser.AddRule(rules...)
	}
	return parser
}

func keyID(material []byte) string {
	sum := sha256.Sum256(material)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type signingKey struct {
	publicKey
	Secret gopaseto.V4AsymmetricSecretKey
}

type publicKey struct {
	KeyID string
	Key   gopaseto.V4AsymmetricPublicKey
	Bytes []byte
}

type localKey struct {
	KeyID string
	Key   gopaseto.V4SymmetricKey
}

type tokenFooter struct {
	KeyID string `json:"kid"`
}
