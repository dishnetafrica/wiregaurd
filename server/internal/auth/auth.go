// Package auth holds the small set of credential primitives: activation
// codes, device tokens, admin passwords and session tokens.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Activation codes look like DN-7K3M-Q2XP-8H4R-W9TN (16 symbols from a
// 32-symbol alphabet = 80 bits of entropy). Ambiguous glyphs are excluded.
const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
const codePrefix = "DN"

// NewActivationCode returns the code to hand to the customer, its hash for
// storage and a short hint for the admin UI.
func NewActivationCode() (code, hash, hint string, err error) {
	raw := make([]byte, 16)
	if _, err = rand.Read(raw); err != nil {
		return
	}
	var sb strings.Builder
	sb.WriteString(codePrefix)
	for i, b := range raw {
		if i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(codeAlphabet[int(b)%len(codeAlphabet)])
	}
	code = sb.String()
	hash = HashCode(code)
	hint = code[3:7]
	return
}

// NormaliseCode makes user input comparable: uppercase, strips spaces and
// dashes, re-inserts the canonical grouping.
func NormaliseCode(in string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(in))
	s = strings.NewReplacer("-", "", " ", "", "_", "").Replace(s)
	if !strings.HasPrefix(s, codePrefix) || len(s) != len(codePrefix)+16 {
		return "", errors.New("activation code format is invalid")
	}
	body := s[len(codePrefix):]
	for _, r := range body {
		if !strings.ContainsRune(codeAlphabet, r) {
			return "", errors.New("activation code contains invalid characters")
		}
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s", codePrefix, body[0:4], body[4:8], body[8:12], body[12:16]), nil
}

// HashCode is a plain SHA-256: the code has 80 bits of entropy from a CSPRNG,
// so a slow KDF adds nothing and a deterministic hash allows an indexed
// lookup without revealing the code in the database.
func HashCode(code string) string {
	sum := sha256.Sum256([]byte("dishnet-activation:" + code))
	return hex.EncodeToString(sum[:])
}

// NewDeviceToken returns a bearer token (256-bit random) and its hash.
func NewDeviceToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return
	}
	token = "dnd_" + base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte("dishnet-token:" + token))
	return hex.EncodeToString(sum[:])
}

// NewSessionToken returns a random admin session token and its hash.
func NewSessionToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

func RandomToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Admin passwords use argon2id (OWASP parameters).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ConstantTimeEqual compares two short strings without leaking length-prefix timing.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
