package unixcrypt

import "testing"

// Vectors from openwall crypt_blowfish's wrapper.c tests[] (the same ones the
// reference ships for $2x$ and $2y$): the password "\xa3" hashed with the
// salt "/OK.fbVrR/bpIqNJ5ianF." at cost 5.
//
//	$2x$ is the sign-extension bug (the key word becomes 0xffffffa3),
//	$2y$ is the corrected algorithm.
//
// Before the fix $2x$ was computed with the standard algorithm, so its output
// was byte-identical to $2y$ and the legacy hash could not be verified.
func TestBcrypt2xSignExtensionVector(t *testing.T) {
	const mcf = "05$/OK.fbVrR/bpIqNJ5ianF."
	const want2x = "$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"
	const want2y = "$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"
	got, err := BcryptFromMCF("\xa3", "2x", mcf)
	if err != nil {
		t.Fatal(err)
	}
	if got != want2x {
		t.Errorf("$2x$ of \\xa3:\n got  %s\n want %s", got, want2x)
	}
	gotY, err := BcryptFromMCF("\xa3", "2y", mcf)
	if err != nil {
		t.Fatal(err)
	}
	if gotY != want2y {
		t.Errorf("$2y$ of \\xa3 (control):\n got  %s\n want %s", gotY, want2y)
	}
}

// TestBcrypt2xEqualsCorrectForASCII: sign extension is a no-op for bytes below
// 0x80, so $2x$ and $2y$ agree on every such password, whatever its length
// (the key cycles over password+NUL, including the 72-byte truncation).
func TestBcrypt2xEqualsCorrectForASCII(t *testing.T) {
	salt := []byte("0123456789abcdef")
	for _, pw := range []string{"", "a", "ab", "abc", "abcd", "password", "U*U*U", "0123456789012345678901234567890123456789012345678901234567890123456789012345"} {
		x, err := Bcrypt(pw, "2x", 4, salt)
		if err != nil {
			t.Fatal(err)
		}
		y, err := Bcrypt(pw, "2y", 4, salt)
		if err != nil {
			t.Fatal(err)
		}
		if x[4:] != y[4:] {
			t.Errorf("password %q: $2x$ %s differs from $2y$ %s", pw, x, y)
		}
	}
}

// TestBcrypt2xDiffersForHighBytes: a byte >= 0x80 changes the $2x$ result.
func TestBcrypt2xDiffersForHighBytes(t *testing.T) {
	salt := []byte("0123456789abcdef")
	x, _ := Bcrypt("pw\xa3", "2x", 4, salt)
	y, _ := Bcrypt("pw\xa3", "2y", 4, salt)
	if x[4:] == y[4:] {
		t.Errorf("$2x$ and $2y$ agree on a password with a byte >= 0x80: %s", x)
	}
}

// TestSignExtendedKey checks the word construction directly: bytes
// 0x01 0xa3 0x02 0x03 form (0x01<<8|0xffffffa3)<<8|2)<<8|3 = 0xffffa302 03...
// computed step by step as the C code does.
func TestSignExtendedKey(t *testing.T) {
	// key = "\x01\xa3" + NUL cycles: 01 a3 00 01 | a3 00 01 a3 | ...
	got := signExtendedKey([]byte{0x01, 0xa3, 0x00})
	if len(got) != 72 {
		t.Fatalf("len = %d, want 72", len(got))
	}
	// First word: ((((0<<8|0x01)<<8)|0xffffffa3)<<8|0)<<8|1
	//   step1: 0x00000001
	//   step2: 0x00000100 | 0xffffffa3 = 0xffffffa3
	//   step3: 0xffffa300 | 0x00000000 = 0xffffa300
	//   step4: 0xffa30000 | 0x00000001 = 0xffa30001
	want := []byte{0xff, 0xa3, 0x00, 0x01}
	for i, b := range want {
		if got[i] != b {
			t.Fatalf("first word = % x, want % x", got[:4], want)
		}
	}
	// ASCII-only key: the plain cycled bytes.
	plain := signExtendedKey([]byte{'a', 'b', 0})
	for i, b := range plain {
		if exp := []byte{'a', 'b', 0}[i%3]; b != exp {
			t.Fatalf("byte %d = %#x, want %#x", i, b, exp)
		}
	}
}
