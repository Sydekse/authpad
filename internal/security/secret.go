package security

import "crypto/subtle"

// EqualSecret compares two secrets in constant time. Length mismatches still
// short-circuit inside ConstantTimeCompare, which is the same tradeoff the
// CSRF middleware already makes for service keys.
func EqualSecret(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
