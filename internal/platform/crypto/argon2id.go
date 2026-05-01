package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const argon2Version = argon2.Version

var (
	// ErrInvalidArgon2Params means the configured Argon2id cost values are not usable.
	ErrInvalidArgon2Params = errors.New("invalid argon2id parameters")
	// ErrInvalidPHCString means an encoded password hash is not a supported PHC string.
	ErrInvalidPHCString = errors.New("invalid argon2id phc string")
)

// Argon2idParams controls password hashing cost and output sizes.
type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// Argon2idHash is a parsed PHC string produced by HashPassword.
type Argon2idHash struct {
	Params Argon2idParams
	Salt   []byte
	Key    []byte
}

// PepperPassword applies the service-wide password pepper as an HMAC-SHA-256
// pre-hash. Store the pepper outside the database.
func PepperPassword(password, pepper []byte) []byte {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write(password)
	return mac.Sum(nil)
}

// HashPassword hashes password with Argon2id and returns an encoded PHC string.
func HashPassword(password, pepper []byte, params Argon2idParams, random io.Reader) (string, error) {
	if err := params.Validate(); err != nil {
		return "", err
	}
	if random == nil {
		return "", errors.New("random reader is required")
	}

	salt := make([]byte, params.SaltLength)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", fmt.Errorf("read argon2id salt: %w", err)
	}

	key := derivePasswordKey(password, pepper, salt, params)
	return encodeArgon2idPHC(params, salt, key), nil
}

// VerifyPassword checks password against an Argon2id PHC string.
func VerifyPassword(password, pepper []byte, encoded string) (bool, error) {
	parsed, err := ParseArgon2idHash(encoded)
	if err != nil {
		return false, err
	}

	key := derivePasswordKey(password, pepper, parsed.Salt, parsed.Params)
	return ConstantTimeEqual(key, parsed.Key), nil
}

// NeedsRehash reports whether encoded was created with parameters different
// from desired.
func NeedsRehash(encoded string, desired Argon2idParams) (bool, error) {
	if err := desired.Validate(); err != nil {
		return false, err
	}
	parsed, err := ParseArgon2idHash(encoded)
	if err != nil {
		return false, err
	}

	return parsed.Params.Memory != desired.Memory ||
		parsed.Params.Iterations != desired.Iterations ||
		parsed.Params.Parallelism != desired.Parallelism ||
		parsed.Params.SaltLength != desired.SaltLength ||
		parsed.Params.KeyLength != desired.KeyLength, nil
}

// ParseArgon2idHash parses a PHC string in the form
// $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<key>.
func ParseArgon2idHash(encoded string) (*Argon2idHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, ErrInvalidPHCString
	}

	if parts[2] != fmt.Sprintf("v=%d", argon2Version) {
		return nil, ErrInvalidPHCString
	}

	params, err := parseArgon2idParams(parts[3])
	if err != nil {
		return nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return nil, ErrInvalidPHCString
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return nil, ErrInvalidPHCString
	}

	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(key))
	if err := params.Validate(); err != nil {
		return nil, err
	}

	return &Argon2idHash{
		Params: params,
		Salt:   salt,
		Key:    key,
	}, nil
}

// Validate checks whether the parameters are usable for Argon2id.
func (p Argon2idParams) Validate() error {
	if p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 || p.SaltLength == 0 || p.KeyLength == 0 {
		return ErrInvalidArgon2Params
	}
	return nil
}

func derivePasswordKey(password, pepper, salt []byte, params Argon2idParams) []byte {
	prehash := PepperPassword(password, pepper)
	return argon2.IDKey(prehash, salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
}

func encodeArgon2idPHC(params Argon2idParams, salt, key []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func parseArgon2idParams(encoded string) (Argon2idParams, error) {
	var params Argon2idParams
	seen := map[string]bool{}

	for _, field := range strings.Split(encoded, ",") {
		name, value, ok := strings.Cut(field, "=")
		if !ok {
			return Argon2idParams{}, ErrInvalidPHCString
		}
		if seen[name] {
			return Argon2idParams{}, ErrInvalidPHCString
		}
		seen[name] = true

		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return Argon2idParams{}, ErrInvalidPHCString
		}

		switch name {
		case "m":
			params.Memory = uint32(n)
		case "t":
			params.Iterations = uint32(n)
		case "p":
			if n > 255 {
				return Argon2idParams{}, ErrInvalidPHCString
			}
			params.Parallelism = uint8(n)
		default:
			return Argon2idParams{}, ErrInvalidPHCString
		}
	}

	if !seen["m"] || !seen["t"] || !seen["p"] {
		return Argon2idParams{}, ErrInvalidPHCString
	}
	return params, nil
}
