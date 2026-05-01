package crypto

import "crypto/subtle"

// ConstantTimeEqual compares a and b without short-circuiting on matching
// lengths. Different lengths still return false.
func ConstantTimeEqual(a, b []byte) bool {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}

	var diff byte
	ap := make([]byte, maxLen)
	bp := make([]byte, maxLen)
	copy(ap, a)
	copy(bp, b)
	for i := 0; i < maxLen; i++ {
		diff |= ap[i] ^ bp[i]
	}

	return subtle.ConstantTimeEq(int32(diff), 0) == 1 &&
		subtle.ConstantTimeEq(int32(len(a)), int32(len(b))) == 1
}
