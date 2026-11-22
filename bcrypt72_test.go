package unixcrypt

import (
	"errors"
	"strings"
	"testing"
)

// bcrypt reads only the first 72 bytes of the password: documented behaviour,
// pinned here (OpenBSD bcrypt.c, crypt_blowfish and golang.org/x/crypto/bcrypt
// before its own 72-byte refusal all truncate the same way).
func TestBcryptTruncatesAtSeventyTwoBytes(t *testing.T) {
	salt := []byte("0123456789abcdef")
	p72 := strings.Repeat("a", 72)
	h72 := must(Bcrypt(p72, "2b", 4, salt))
	for _, pw := range []string{p72 + "b", p72 + "bcd", p72 + "zzzz"} {
		if got := must(Bcrypt(pw, "2b", 4, salt)); got != h72 {
			t.Errorf("%d-byte password: %s, want the 72-byte hash %s", len(pw), got, h72)
		}
	}
	// The 72nd byte is used: a 71-byte password differs.
	if got := must(Bcrypt(p72[:71], "2b", 4, salt)); got == h72 {
		t.Error("71-byte and 72-byte passwords hash equally")
	}
}

func TestBcryptStrictRefusesAboveSeventyTwo(t *testing.T) {
	salt := []byte("0123456789abcdef")
	p72 := strings.Repeat("a", 72)
	for _, n := range []int{73, 76, 200} {
		if got, err := BcryptStrict(p72+strings.Repeat("b", n-72), "2b", 4, salt); !errors.Is(err, ErrPasswordTooLong) || got != "" {
			t.Errorf("BcryptStrict(%d bytes) = %q, %v; want ErrPasswordTooLong", n, got, err)
		}
	}
	// At the limit it equals Bcrypt.
	if got, err := BcryptStrict(p72, "2b", 4, salt); err != nil || got != must(Bcrypt(p72, "2b", 4, salt)) {
		t.Errorf("BcryptStrict(72 bytes) = %q, %v", got, err)
	}
	// Other errors still come from Bcrypt.
	if _, err := BcryptStrict("pw", "2b", 4, salt[:3]); err == nil || errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("short salt: err = %v", err)
	}
}

// A NUL inside the password does not end it: the bytes after it count.
func TestBcryptNULDoesNotTerminate(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := must(Bcrypt("ab\x00cd", "2b", 4, salt))
	b := must(Bcrypt("ab\x00ce", "2b", 4, salt))
	if a == b {
		t.Error("bytes after a NUL are ignored")
	}
}
