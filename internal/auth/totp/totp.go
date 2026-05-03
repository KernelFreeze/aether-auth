package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	platformcrypto "github.com/KernelFreeze/aether-auth/internal/platform/crypto"
)

const (
	defaultIssuer     = "Aether Auth"
	defaultSecretSize = 20
	defaultDigits     = 6
	defaultPeriod     = 30 * time.Second
	defaultSkew       = 1
	algorithmSHA1     = "SHA1"
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ProvisioningURIRequest contains the client-visible TOTP enrollment values.
type ProvisioningURIRequest struct {
	Issuer      string
	AccountName string
	Secret      string
	Digits      int
	Period      time.Duration
}

// GenerateSecret returns a base32 TOTP secret using random bytes.
func GenerateSecret(random io.Reader, size int) (string, error) {
	if size <= 0 {
		size = defaultSecretSize
	}
	secret, err := platformcrypto.RandomBytesFrom(random, size)
	if err != nil {
		return "", fmt.Errorf("totp: generate secret: %w", err)
	}
	return base32NoPadding.EncodeToString(secret), nil
}

// ProvisioningURI returns an otpauth URI suitable for authenticator apps.
func ProvisioningURI(req ProvisioningURIRequest) (string, error) {
	issuer := defaultString(req.Issuer, defaultIssuer)
	accountName := strings.TrimSpace(req.AccountName)
	secret := normalizeSecret(req.Secret)
	if accountName == "" || secret == "" {
		return "", errors.New("totp issuer account and secret are required")
	}
	if _, err := decodeSecret(secret); err != nil {
		return "", err
	}

	digits := req.Digits
	if digits <= 0 {
		digits = defaultDigits
	}
	period := req.Period
	if period <= 0 {
		period = defaultPeriod
	}

	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", issuer)
	values.Set("algorithm", algorithmSHA1)
	values.Set("digits", strconv.Itoa(digits))
	values.Set("period", strconv.FormatInt(int64(period/time.Second), 10))
	label := url.PathEscape(issuer + ":" + accountName)
	return "otpauth://totp/" + label + "?" + values.Encode(), nil
}

// GenerateCode returns the TOTP code for secret at now.
func GenerateCode(secret string, now time.Time, digits int, period time.Duration) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	if digits <= 0 {
		digits = defaultDigits
	}
	if period <= 0 {
		period = defaultPeriod
	}
	if digits > 9 {
		return "", errors.New("totp digits must be 9 or fewer")
	}
	counter := uint64(now.Unix() / int64(period/time.Second))
	return hotp(key, counter, digits), nil
}

// ValidateCode reports whether code matches secret at now within skew windows.
func ValidateCode(secret, code string, now time.Time, digits int, period time.Duration, skew int) (bool, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}
	if digits <= 0 {
		digits = defaultDigits
	}
	if len(code) != digits || !digitsOnly(code) {
		return false, nil
	}
	if period <= 0 {
		period = defaultPeriod
	}
	if skew < 0 {
		skew = 0
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return false, err
	}

	counter := now.Unix() / int64(period/time.Second)
	for offset := -skew; offset <= skew; offset++ {
		nextCounter := counter + int64(offset)
		if nextCounter < 0 {
			continue
		}
		expected := hotp(key, uint64(nextCounter), digits)
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true, nil
		}
	}
	return false, nil
}

func hotp(key []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset : offset+4])
	value &= 0x7fffffff
	modulo := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, value%modulo)
}

func decodeSecret(secret string) ([]byte, error) {
	secret = normalizeSecret(secret)
	if secret == "" {
		return nil, errors.New("totp secret is required")
	}
	decoded, err := base32NoPadding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("totp: decode secret: %w", err)
	}
	return decoded, nil
}

func normalizeSecret(secret string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
}

func digitsOnly(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
