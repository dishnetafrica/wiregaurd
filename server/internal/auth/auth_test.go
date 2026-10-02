package auth

import (
	"strings"
	"testing"
)

func TestActivationCodeRoundTrip(t *testing.T) {
	code, hash, hint, err := NewActivationCode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, "DN-") || len(code) != 22 {
		t.Fatalf("code format %q", code)
	}
	if hint != code[3:7] {
		t.Fatalf("hint %q for %q", hint, code)
	}
	for _, in := range []string{code, strings.ToLower(code), strings.ReplaceAll(code, "-", ""), " " + code + " "} {
		n, err := NormaliseCode(in)
		if err != nil || n != code || HashCode(n) != hash {
			t.Fatalf("normalise %q -> %q (%v)", in, n, err)
		}
	}
	for _, bad := range []string{"", "DN-1111-1111-1111-1111", "XX-ABCD-ABCD-ABCD-ABCD", code + "A"} {
		if _, err := NormaliseCode(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

func TestPasswords(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "correct horse batterx") || VerifyPassword("garbage", "x") {
		t.Fatal("verify mismatch")
	}
}

func TestTokens(t *testing.T) {
	tok, hash, err := NewDeviceToken()
	if err != nil || !strings.HasPrefix(tok, "dnd_") || HashToken(tok) != hash || len(tok) < 40 {
		t.Fatalf("token %q hash %q err %v", tok, hash, err)
	}
	tok2, _, _ := NewDeviceToken()
	if tok == tok2 {
		t.Fatal("tokens must be unique")
	}
}
