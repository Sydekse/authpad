package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Version = 0x13
)

// Argon2Params defines Argon2id parameters.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params returns OWASP-recommended parameters.
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Memory:      64 * 1024, // 64 MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// PasswordService hashes and verifies passwords with Argon2id + salt + pepper.
type PasswordService struct {
	pepper []byte
	params *Argon2Params
}

// NewPasswordService creates a PasswordService. pepperKey must be base64-encoded.
func NewPasswordService(pepperKey string) (*PasswordService, error) {
	var pepper []byte
	if pepperKey != "" {
		var err error
		pepper, err = base64.StdEncoding.DecodeString(pepperKey)
		if err != nil {
			return nil, fmt.Errorf("invalid pepper key: %w", err)
		}
	}
	return &PasswordService{
		pepper: pepper,
		params: DefaultArgon2Params(),
	}, nil
}

// Hash produces an Argon2id hash of the password (with pepper). Salt is generated randomly.
func (ps *PasswordService) Hash(password string) (string, error) {
	salt := make([]byte, ps.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	peppered := append([]byte(password), ps.pepper...)
	hash := argon2.IDKey(
		peppered,
		salt,
		ps.params.Iterations,
		ps.params.Memory,
		ps.params.Parallelism,
		ps.params.KeyLength,
	)

	return ps.encode(hash, salt), nil
}

// Verify checks the password against the stored encoded hash. Uses constant-time comparison.
func (ps *PasswordService) Verify(password, encodedHash string) (bool, error) {
	hash, salt, params, err := ps.decode(encodedHash)
	if err != nil {
		return false, err
	}

	peppered := append([]byte(password), ps.pepper...)
	computed := argon2.IDKey(
		peppered,
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return subtle.ConstantTimeCompare(hash, computed) == 1, nil
}

func (ps *PasswordService) encode(hash, salt []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version,
		ps.params.Memory,
		ps.params.Iterations,
		ps.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func (ps *PasswordService) decode(encoded string) (hash, salt []byte, params *Argon2Params, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("invalid argon2 hash format")
	}

	var v, m, t uint32
	var p uint8
	_, _ = fmt.Sscanf(parts[2], "v=%d", &v)
	_, _ = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p)

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}

	params = &Argon2Params{Memory: m, Iterations: t, Parallelism: p, SaltLength: uint32(len(salt)), KeyLength: uint32(len(hash))}
	_ = v
	return hash, salt, params, nil
}
