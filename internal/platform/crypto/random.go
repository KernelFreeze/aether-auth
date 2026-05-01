package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// RandomBytes returns n bytes from the process CSPRNG.
func RandomBytes(n int) ([]byte, error) {
	return RandomBytesFrom(rand.Reader, n)
}

// RandomBytesFrom returns n bytes from random.
func RandomBytesFrom(random io.Reader, n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("random byte length must be non-negative")
	}
	if random == nil {
		return nil, errors.New("random reader is required")
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(random, buf); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return buf, nil
}

// RandomString returns an unbiased random string of length n from alphabet.
func RandomString(n int, alphabet string) (string, error) {
	return RandomStringFrom(rand.Reader, n, alphabet)
}

// RandomStringFrom returns an unbiased random string of length n from alphabet
// using random as the entropy source.
func RandomStringFrom(random io.Reader, n int, alphabet string) (string, error) {
	if n < 0 {
		return "", errors.New("random string length must be non-negative")
	}
	symbols := []rune(alphabet)
	if len(symbols) == 0 {
		return "", errors.New("random string alphabet is required")
	}
	if random == nil {
		return "", errors.New("random reader is required")
	}

	max := big.NewInt(int64(len(symbols)))
	out := make([]rune, n)
	for i := range out {
		j, err := rand.Int(random, max)
		if err != nil {
			return "", fmt.Errorf("read random index: %w", err)
		}
		out[i] = symbols[j.Int64()]
	}
	return string(out), nil
}
