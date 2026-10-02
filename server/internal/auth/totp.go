package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Time-based one-time passwords (RFC 6238, SHA-1, 6 digits, 30 s) as used by
// Google Authenticator, Microsoft Authenticator, Aegis and others.

const totpPeriod = 30

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh 160-bit secret in base32.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// TOTPCode computes the code for a secret at time t.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("bad secret: %w", err)
	}
	counter := uint64(t.Unix() / totpPeriod)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// VerifyTOTP accepts the current code and the one period either side (clock drift).
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return false
	}
	for _, d := range []int{0, -1, 1} {
		want, err := TOTPCode(secret, now.Add(time.Duration(d*totpPeriod)*time.Second))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// TOTPURI is what the authenticator app scans (as a QR code).
func TOTPURI(issuer, account, secret string) string {
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?secret=" + secret + "&issuer=" + url.QueryEscape(issuer) + "&algorithm=SHA1&digits=6&period=30"
}
