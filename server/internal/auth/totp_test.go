package auth

import (
	"testing"
	"time"
)

// RFC 6238 appendix B vectors (SHA-1, secret "12345678901234567890"), truncated to 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		at   int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		got, err := TOTPCode(secret, time.Unix(tc.at, 0))
		if err != nil || got != tc.want {
			t.Fatalf("t=%d: got %q err=%v want %q", tc.at, got, err, tc.want)
		}
	}
	now := time.Unix(1111111111, 0)
	if !VerifyTOTP(secret, "050471", now) || !VerifyTOTP(secret, "081804", now) /* previous period */ || VerifyTOTP(secret, "287082", now) {
		t.Fatal("verify window wrong")
	}
	s, _ := NewTOTPSecret()
	if len(s) != 32 {
		t.Fatalf("secret length %d", len(s))
	}
}
