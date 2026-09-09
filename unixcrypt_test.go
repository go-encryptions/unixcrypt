package unixcrypt

import (
	"strings"
	"testing"
)

// Reference values below are real `openssl passwd` output (OpenSSL 3.6.4),
// cross-checked against the previously-shipped go-puppet/puppet
// implementation this package was extracted from, plus the canonical
// OpenBSD bcrypt.c test vectors for the bcrypt cases.

func TestMD5Crypt(t *testing.T) {
	got := MD5Crypt("secret", "abc123")
	want := "$1$abc123$5IJcAgUIzNOMrV9cXyMFd1"
	if got != want {
		t.Errorf("MD5Crypt = %q, want %q", got, want)
	}
}

func TestMD5CryptLongPassword(t *testing.T) {
	// Exercises the >16-byte branches of the inner digest-folding loops
	// (real crypt(3) MD5-crypt folds the password in 16-byte chunks).
	got := MD5Crypt("this-password-is-longer-than-sixteen-bytes", "abc123")
	if len(got) == 0 || got[:3] != "$1$" {
		t.Fatalf("MD5Crypt(long password) = %q, want a well-formed $1$ hash", got)
	}
	// Determinism: hashing the same long password+salt twice must agree.
	if got2 := MD5Crypt("this-password-is-longer-than-sixteen-bytes", "abc123"); got != got2 {
		t.Errorf("MD5Crypt(long password) not deterministic: %q vs %q", got, got2)
	}
}

func TestSHA256CryptDefault(t *testing.T) {
	got := SHA256Crypt("secret", "abc123", 0)
	want := "$5$abc123$wRJRuAN8mQOchT827qNg5d1eE/hXqPDshKnDFtr5Ny2"
	if got != want {
		t.Errorf("SHA256Crypt(rounds=0) = %q, want %q", got, want)
	}
}

func TestSHA512CryptDefault(t *testing.T) {
	got := SHA512Crypt("secret", "abc123", 0)
	want := "$6$abc123$658Dwx.o8ZaF5yCkRyY/MrvTU271tISGpwvd6zNaAjewb8ayeuf4FxTkJ60ipw4l7UGpyAJy40AGqB3EH4P3L0"
	if got != want {
		t.Errorf("SHA512Crypt(rounds=0) = %q, want %q", got, want)
	}
}

func TestSHA512CryptExplicitRounds(t *testing.T) {
	got := SHA512Crypt("secret", "abc123", 10000)
	want := "$6$rounds=10000$abc123$Z5HMbHsuGm9Y/O40xGGRe46SY51vnbt/dNLda1MMNMYi6vNmSYjFcGCre8GBI36M7KlPACMuZ7IiXkKj8OZRt/"
	if got != want {
		t.Errorf("SHA512Crypt(rounds=10000) = %q, want %q", got, want)
	}
}

func TestSHA256CryptExplicitRounds(t *testing.T) {
	got := SHA256Crypt("secret", "abc123", 100000)
	want := "$5$rounds=100000$abc123$BAypCR.piwV2RkOutF15YIYEZOxdkqWo1rCdmX0Rlf3"
	if got != want {
		t.Errorf("SHA256Crypt(rounds=100000) = %q, want %q", got, want)
	}
}

func TestSHA512CryptRoundsClampedToMin(t *testing.T) {
	// Real crypt(3) clamps any requested round count below 1000 up to
	// 1000 — confirmed against real `openssl passwd -6 -salt
	// 'rounds=500$abc123'`, which produces byte-identical output to an
	// explicit rounds=1000 request.
	got500 := SHA512Crypt("secret", "abc123", 500)
	want := "$6$rounds=1000$abc123$rqoM2yfLyxmA/mlZhhi/gN4FjF2Rgy5kekfNvVVhAmZQkbzRdjsSmtUogL1oCT.r88ujPiuPRR2DeBgg67rbe0"
	if got500 != want {
		t.Errorf("SHA512Crypt(rounds=500) = %q, want %q (clamped to 1000)", got500, want)
	}
	got1000 := SHA512Crypt("secret", "abc123", 1000)
	if got1000 != want {
		t.Errorf("SHA512Crypt(rounds=1000) = %q, want %q", got1000, want)
	}
}

func TestSHA512CryptExplicitDefaultRoundsStillPrintsPrefix(t *testing.T) {
	// A real, easy-to-miss detail confirmed against real openssl: passing
	// rounds=5000 EXPLICITLY still prints "rounds=5000$" in the output,
	// even though 5000 is also the implicit default used when rounds==0
	// (which omits the prefix entirely). The digest itself is identical
	// either way — only the prefix differs.
	explicit := SHA512Crypt("secret", "abc123", 5000)
	want := "$6$rounds=5000$abc123$658Dwx.o8ZaF5yCkRyY/MrvTU271tISGpwvd6zNaAjewb8ayeuf4FxTkJ60ipw4l7UGpyAJy40AGqB3EH4P3L0"
	if explicit != want {
		t.Errorf("SHA512Crypt(rounds=5000) = %q, want %q", explicit, want)
	}
	implicit := SHA512Crypt("secret", "abc123", 0)
	if strings.Contains(implicit, "rounds=") {
		t.Errorf("SHA512Crypt(rounds=0) = %q, want no rounds= prefix", implicit)
	}
}

func TestClampRounds(t *testing.T) {
	// MaxRounds/MinRounds themselves (999999999/1000) are real crypt(3)/
	// libxcrypt's own documented clamp bounds (Drepper's spec) — the
	// clamp LOGIC is unit-tested directly here rather than through
	// SHA512Crypt, since actually running anywhere near 999999999 real
	// SHA-512 rounds in a test would take minutes.
	cases := []struct {
		requested    int
		wantN        int
		wantExplicit bool
	}{
		{0, DefaultRounds, false},
		{5000, DefaultRounds, true},
		{500, MinRounds, true},
		{1000, MinRounds, true},
		{MaxRounds + 1000000, MaxRounds, true},
		{10000, 10000, true},
	}
	for _, c := range cases {
		n, explicit := clampRounds(c.requested)
		if n != c.wantN || explicit != c.wantExplicit {
			t.Errorf("clampRounds(%d) = (%d, %v), want (%d, %v)", c.requested, n, explicit, c.wantN, c.wantExplicit)
		}
	}
}

func TestBcryptOpenBSDVectors(t *testing.T) {
	salt := bcryptB64Decode("CCCCCCCCCCCCCCCCCCCCC.")[:16]

	got, err := Bcrypt("U*U", "2a", 5, salt)
	if err != nil {
		t.Fatal(err)
	}
	if want := "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"; got != want {
		t.Errorf("Bcrypt(U*U) = %q, want %q", got, want)
	}

	got, err = Bcrypt("U*U*", "2a", 5, salt)
	if err != nil {
		t.Fatal(err)
	}
	if want := "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"; got != want {
		t.Errorf("Bcrypt(U*U*) = %q, want %q", got, want)
	}
}

func TestBcryptModernPrefix(t *testing.T) {
	salt := bcryptB64Decode("cgT08pfGUo9SUIIvXrIJ1u")[:16]
	got, err := Bcrypt("password", "2b", 10, salt)
	if err != nil {
		t.Fatal(err)
	}
	if want := "$2b$10$cgT08pfGUo9SUIIvXrIJ1uSXp0VJmOIKgEC6vqGvqRddK4Z3JB28G"; got != want {
		t.Errorf("Bcrypt(2b) = %q, want %q", got, want)
	}
}

func TestBcryptFromMCF(t *testing.T) {
	got, err := BcryptFromMCF("password", "2b", "10$cgT08pfGUo9SUIIvXrIJ1u")
	if err != nil {
		t.Fatal(err)
	}
	if want := "$2b$10$cgT08pfGUo9SUIIvXrIJ1uSXp0VJmOIKgEC6vqGvqRddK4Z3JB28G"; got != want {
		t.Errorf("BcryptFromMCF = %q, want %q", got, want)
	}

	if _, err := BcryptFromMCF("password", "2b", "not-a-valid-salt"); err == nil {
		t.Fatal("BcryptFromMCF with a malformed salt: got nil error, want one")
	}
	if _, err := BcryptFromMCF("password", "2b", "xx$cgT08pfGUo9SUIIvXrIJ1u"); err == nil {
		t.Fatal("BcryptFromMCF with a non-numeric cost: got nil error, want one")
	}
	if _, err := BcryptFromMCF("password", "2b", "10$tooshort"); err == nil {
		t.Fatal("BcryptFromMCF with a too-short salt: got nil error, want one")
	}
}

func TestBcryptErrors(t *testing.T) {
	if _, err := Bcrypt("password", "2b", 10, make([]byte, 15)); err == nil {
		t.Fatal("Bcrypt with a 15-byte salt: got nil error, want one")
	}
	if _, err := Bcrypt("password", "2b", 3, make([]byte, 16)); err == nil {
		t.Fatal("Bcrypt with cost 3 (below the 4-31 range): got nil error, want one")
	}
	if _, err := Bcrypt("password", "2b", 32, make([]byte, 16)); err == nil {
		t.Fatal("Bcrypt with cost 32 (above the 4-31 range): got nil error, want one")
	}
}

func TestValidSaltChars(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"abc123./ABC", true},
		{"", true},
		{"has space", false},
		{"has$dollar", false},
	}
	for _, c := range cases {
		if got := ValidSaltChars(c.s); got != c.want {
			t.Errorf("ValidSaltChars(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestRandomSalt(t *testing.T) {
	s, err := RandomSalt(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 16 {
		t.Fatalf("RandomSalt(16) length = %d, want 16", len(s))
	}
	if !ValidSaltChars(s) {
		t.Errorf("RandomSalt(16) = %q, contains invalid salt characters", s)
	}

	s2, err := RandomSalt(16)
	if err != nil {
		t.Fatal(err)
	}
	if s == s2 {
		t.Error("two RandomSalt(16) calls produced the same salt — suspicious for a real random source")
	}

	if _, err := RandomSalt(0); err == nil {
		t.Fatal("RandomSalt(0): got nil error, want one")
	}
	if _, err := RandomSalt(-1); err == nil {
		t.Fatal("RandomSalt(-1): got nil error, want one")
	}
}
