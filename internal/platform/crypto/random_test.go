package crypto_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/KernelFreeze/aether-auth/internal/platform/crypto"
)

func TestRandomBytesFrom(t *testing.T) {
	got, err := crypto.RandomBytesFrom(bytes.NewReader([]byte{1, 2, 3}), 3)
	if err != nil {
		t.Fatalf("RandomBytesFrom() error = %v", err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("RandomBytesFrom() = %v, want [1 2 3]", got)
	}
}

func TestRandomStringFrom(t *testing.T) {
	got, err := crypto.RandomStringFrom(bytes.NewReader(bytes.Repeat([]byte{0}, 16)), 8, "abc")
	if err != nil {
		t.Fatalf("RandomStringFrom() error = %v", err)
	}
	if got != "aaaaaaaa" {
		t.Fatalf("RandomStringFrom() = %q, want %q", got, "aaaaaaaa")
	}
}

func TestRandomHelpersRejectInvalidInput(t *testing.T) {
	if _, err := crypto.RandomBytesFrom(nil, 1); err == nil {
		t.Fatal("RandomBytesFrom() nil reader error = nil, want error")
	}
	if _, err := crypto.RandomBytesFrom(bytes.NewReader(nil), -1); err == nil {
		t.Fatal("RandomBytesFrom() negative length error = nil, want error")
	}
	if _, err := crypto.RandomBytesFrom(bytes.NewReader(nil), 1); !errors.Is(err, io.EOF) {
		t.Fatalf("RandomBytesFrom() short reader error = %v, want EOF", err)
	}

	if _, err := crypto.RandomStringFrom(nil, 1, "abc"); err == nil {
		t.Fatal("RandomStringFrom() nil reader error = nil, want error")
	}
	if _, err := crypto.RandomStringFrom(bytes.NewReader(nil), -1, "abc"); err == nil {
		t.Fatal("RandomStringFrom() negative length error = nil, want error")
	}
	if _, err := crypto.RandomStringFrom(bytes.NewReader(nil), 1, ""); err == nil {
		t.Fatal("RandomStringFrom() empty alphabet error = nil, want error")
	}
	if _, err := crypto.RandomStringFrom(bytes.NewReader(nil), 1, "abc"); !strings.Contains(err.Error(), "read random index") {
		t.Fatalf("RandomStringFrom() short reader error = %v, want read random index", err)
	}
}
