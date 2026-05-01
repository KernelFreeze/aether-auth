package crypto_test

import (
	"testing"

	"github.com/KernelFreeze/aether-auth/internal/platform/crypto"
)

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{name: "same", a: []byte("secret"), b: []byte("secret"), want: true},
		{name: "different value", a: []byte("secret"), b: []byte("secRet"), want: false},
		{name: "different length", a: []byte("secret"), b: []byte("secret!"), want: false},
		{name: "both empty", a: nil, b: nil, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crypto.ConstantTimeEqual(tt.a, tt.b); got != tt.want {
				t.Fatalf("ConstantTimeEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
