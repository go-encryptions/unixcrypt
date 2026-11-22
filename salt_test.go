package unixcrypt

import (
	"errors"
	"testing"
)

// Reference values are real `openssl passwd` output (OpenSSL 3.5.8).
func TestMD5CryptSaltTruncatedToEight(t *testing.T) {
	got := must(MD5Crypt("password", "123456789abc"))
	if want := "$1$12345678$o2n/JiO/h5VviOInWJ4OQ/"; got != want {
		t.Errorf("MD5Crypt long salt = %q, want %q", got, want)
	}
	if got := must(MD5Crypt("password", "0123456789abcdef")); got != "$1$01234567$b5lh2mHyD2PdJjFfALlEz1" {
		t.Errorf("MD5Crypt 16-char salt = %q", got)
	}
}

func TestMD5CryptSaltEndsAtDollar(t *testing.T) {
	a := must(MD5Crypt("password", "ab$cd"))
	b := must(MD5Crypt("password", "ab"))
	if a != b || a[:6] != "$1$ab$" {
		t.Errorf("salt with '$': %q, want the same as salt \"ab\": %q", a, b)
	}
}

func TestSaltRejectsInvalidChars(t *testing.T) {
	for _, salt := range []string{"a b", "ab:c", "ab\n", "é", "a=b"} {
		if _, err := MD5Crypt("pw", salt); !errors.Is(err, ErrBadSalt) {
			t.Errorf("MD5Crypt salt %q: err = %v, want ErrBadSalt", salt, err)
		}
		if _, err := SHA256Crypt("pw", salt, 0); !errors.Is(err, ErrBadSalt) {
			t.Errorf("SHA256Crypt salt %q: err = %v, want ErrBadSalt", salt, err)
		}
		if _, err := SHA512Crypt("pw", salt, 0); !errors.Is(err, ErrBadSalt) {
			t.Errorf("SHA512Crypt salt %q: err = %v, want ErrBadSalt", salt, err)
		}
	}
	// Only the part kept after truncation is validated, as crypt(3) does.
	if _, err := MD5Crypt("pw", "abcdefgh=ignored"); err != nil {
		t.Errorf("characters past the 8th are dropped, got %v", err)
	}
}

func TestSHACryptSaltInRounds(t *testing.T) {
	got := must(SHA512Crypt("pw", "rounds=1000$ab", 0))
	want := "$6$rounds=1000$ab$8/vdebh7.eIeNufFrLK0jMMqafLdKpZbPY1ppG7x22R2yDSMj7XkxuEn2jtBuNS.VYAmIhpV6haXB82POC/MC0"
	if got != want {
		t.Errorf("rounds in salt = %q, want %q", got, want)
	}
	if viaParam := must(SHA512Crypt("pw", "ab", 1000)); viaParam != want {
		t.Errorf("rounds as parameter = %q, want %q", viaParam, want)
	}
	if _, err := SHA512Crypt("pw", "rounds=1000$ab", 2000); !errors.Is(err, ErrBadSalt) {
		t.Errorf("rounds in salt and parameter: err = %v, want ErrBadSalt", err)
	}
}

func TestSHACryptSaltEndsAtDollar(t *testing.T) {
	a := must(SHA256Crypt("pw", "a$b", 0))
	b := must(SHA256Crypt("pw", "a", 0))
	if a != b || a[:5] != "$5$a$" {
		t.Errorf("salt with '$': %q, want the same as salt \"a\": %q", a, b)
	}
	// Truncation to 16 characters (openssl: $5$abcdefghijklmnop$gu.71Qn...).
	if got := must(SHA256Crypt("pw", "abcdefghijklmnopqrstuvwxyz", 0)); got != "$5$abcdefghijklmnop$gu.71QnGu.GrGbdJF.mj20x/mWJF1VliZRmeYNpAtDB" {
		t.Errorf("long salt = %q", got)
	}
}

func TestNormalizeSaltAndDigits(t *testing.T) {
	if isAllDigits("") || !isAllDigits("0123456789") || isAllDigits("12a") || isAllDigits("1 ") {
		t.Error("isAllDigits misjudged")
	}
	if s, err := normalizeSalt("abcdef", 6); err != nil || s != "abcdef" {
		t.Errorf("normalizeSalt at the limit = %q, %v", s, err)
	}
	if s, _ := normalizeSalt("abcdefg", 6); s != "abcdef" {
		t.Errorf("normalizeSalt over the limit = %q", s)
	}
}

func TestSHACryptSaltRoundsEdge(t *testing.T) {
	// rounds=0 in the salt is clamped up to MinRounds (libxcrypt); an
	// overflowing count is clamped down to MaxRounds without running 1e9
	// rounds here, so only the parsing path is exercised through clampRounds.
	got := must(SHA256Crypt("pw", "rounds=0$ab", 0))
	if want := must(SHA256Crypt("pw", "ab", MinRounds)); got != want {
		t.Errorf("rounds=0 in salt = %q, want %q", got, want)
	}
	// A "rounds=" salt without a terminating '$' or with a non-numeric
	// count is just a salt, and '=' is not a salt character.
	for _, salt := range []string{"rounds=1000", "rounds=x$ab"} {
		if _, err := SHA256Crypt("pw", salt, 0); !errors.Is(err, ErrBadSalt) {
			t.Errorf("salt %q: err = %v, want ErrBadSalt", salt, err)
		}
	}
}
