package unixcrypt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestSHACryptPasswordCap is the regression test for the quadratic SHA-crypt
// cost: a password above MaxPasswordLen is refused before any hashing.
// Before the fix a 64 KiB password at rounds=1000 cost 6.5 s of CPU (16 KiB:
// 312 ms, a ratio of 20.8 for 4x the length).
func TestSHACryptPasswordCap(t *testing.T) {
	for _, n := range []int{MaxPasswordLen + 1, 16 << 10, 64 << 10} {
		pw := strings.Repeat("x", n)
		start := time.Now()
		for name, f := range map[string]func(string, string, int) (string, error){
			"SHA256Crypt": SHA256Crypt,
			"SHA512Crypt": SHA512Crypt,
		} {
			got, err := f(pw, "salt", 1000)
			if !errors.Is(err, ErrPasswordTooLong) {
				t.Errorf("%s(%d bytes) = %q, %v; want ErrPasswordTooLong", name, n, got, err)
			}
			if got != "" {
				t.Errorf("%s(%d bytes) returned a hash alongside the error: %q", name, n, got)
			}
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("refusing a %d-byte password took %v; the check must come before the hashing", n, d)
		}
	}
}

// TestSHACryptLongPasswordKAT pins a known answer for a long accepted
// password. Oracle: OpenSSL 4.1.0, `openssl passwd -6 -salt abc123 -in <file
// of 200 x's, no newline>` (and -5). The oracle stops at 200 because
// `openssl passwd` reads a password through a 256-byte buffer.
func TestSHACryptLongPasswordKAT(t *testing.T) {
	pw := strings.Repeat("x", 200)
	want6 := "$6$abc123$a8tXmjsY3E1H4zmn/9FeGyAUAiuBJdFEo79D2KvQzuOtwz9AOOtwYhPo8W2GvG3Vji3aLGtuqf5AtyPPS4aoS."
	if got := must(SHA512Crypt(pw, "abc123", 0)); got != want6 {
		t.Errorf("SHA512Crypt(200 bytes) = %q, want %q", got, want6)
	}
	want5 := "$5$abc123$qDT7WC198iPZPcunBMoHgMjB01.tspog1VxpZD6FX26"
	if got := must(SHA256Crypt(pw, "abc123", 0)); got != want5 {
		t.Errorf("SHA256Crypt(200 bytes) = %q, want %q", got, want5)
	}
}

// TestSHACryptPasswordAtCap pins the boundary: libxcrypt's
// CRYPT_MAX_PASSPHRASE_SIZE is 512 counting the terminating NUL
// (lib/crypt.h.in), so 511 bytes are accepted and 512 are refused.
func TestSHACryptPasswordAtCap(t *testing.T) {
	if MaxPasswordLen != 511 {
		t.Fatalf("MaxPasswordLen = %d, want 511", MaxPasswordLen)
	}
	pw := strings.Repeat("x", MaxPasswordLen)
	if _, err := SHA512Crypt(pw, "abc123", 0); err != nil {
		t.Errorf("SHA512Crypt(511 bytes): %v", err)
	}
	if _, err := SHA256Crypt(pw, "abc123", 0); err != nil {
		t.Errorf("SHA256Crypt(511 bytes): %v", err)
	}
	if _, err := SHA512Crypt(pw+"x", "abc123", 0); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("SHA512Crypt(512 bytes) error = %v, want ErrPasswordTooLong", err)
	}
}
