// Package unixcrypt implements crypt(3)/MCF (Modular Crypt Format) password
// hash algorithms in pure Go (CGO=0): MD5-crypt ($1$), SHA-256-crypt ($5$)
// and SHA-512-crypt ($6$) per Ulrich Drepper's specification
// (https://www.akkadia.org/drepper/SHA-crypt.txt), and bcrypt ($2a$/$2b$/
// $2x$/$2y$) via the pure-Go blowfish primitive. No component depends on
// libc's own crypt(3) or cgo; every output was validated against real
// `openssl passwd` and the canonical OpenBSD bcrypt test vectors.
package unixcrypt

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/blowfish"
)

// --- crypt(3) base64 -------------------------------------------------------

const cryptB64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// SaltChars is the character set every crypt(3) implementation accepts in a
// salt: base64-like, but with "./" instead of "+/".
const SaltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"

// ValidSaltChars reports whether every character in s is a valid crypt(3)
// salt character.
func ValidSaltChars(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune(SaltChars, c) {
			return false
		}
	}
	return true
}

// RandomSalt returns a cryptographically random salt string of length n
// drawn from SaltChars, using crypto/rand.
func RandomSalt(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("unixcrypt: salt length must be positive, got %d", n)
	}
	idx := make([]byte, n)
	if _, err := rand.Read(idx); err != nil {
		return "", fmt.Errorf("unixcrypt: generating random salt: %w", err)
	}
	out := make([]byte, n)
	for i, b := range idx {
		out[i] = SaltChars[int(b)%len(SaltChars)]
	}
	return string(out), nil
}

// b64From24 emits n crypt-base64 chars from the 24-bit value b2<<16|b1<<8|b0.
func b64From24(b2, b1, b0 byte, n int, out []byte) []byte {
	w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
	for ; n > 0; n-- {
		out = append(out, cryptB64[w&0x3f])
		w >>= 6
	}
	return out
}

// --- MD5-crypt ($1$) --------------------------------------------------------

// MD5Crypt computes the classic MD5-crypt ($1$) hash of password with salt
// (created by Poul-Henning Kamp for FreeBSD, later adopted by glibc).
func MD5Crypt(password, salt string) string {
	const magic = "$1$"
	pw := []byte(password)
	s := []byte(salt)

	b := md5.New()
	b.Write(pw)
	b.Write(s)
	b.Write(pw)
	alt := b.Sum(nil)

	a := md5.New()
	a.Write(pw)
	a.Write([]byte(magic))
	a.Write(s)
	for i := len(pw); i > 0; i -= 16 {
		if i > 16 {
			a.Write(alt[:16])
		} else {
			a.Write(alt[:i])
		}
	}
	for i := len(pw); i > 0; i >>= 1 {
		if i&1 == 1 {
			a.Write([]byte{0})
		} else {
			a.Write(pw[:1])
		}
	}
	sum := a.Sum(nil)

	for i := 0; i < 1000; i++ {
		c := md5.New()
		if i&1 == 1 {
			c.Write(pw)
		} else {
			c.Write(sum)
		}
		if i%3 != 0 {
			c.Write(s)
		}
		if i%7 != 0 {
			c.Write(pw)
		}
		if i&1 == 1 {
			c.Write(sum)
		} else {
			c.Write(pw)
		}
		sum = c.Sum(nil)
	}

	out := make([]byte, 0, 34)
	out = append(out, magic...)
	out = append(out, s...)
	out = append(out, '$')
	out = b64From24(sum[0], sum[6], sum[12], 4, out)
	out = b64From24(sum[1], sum[7], sum[13], 4, out)
	out = b64From24(sum[2], sum[8], sum[14], 4, out)
	out = b64From24(sum[3], sum[9], sum[15], 4, out)
	out = b64From24(sum[4], sum[10], sum[5], 4, out)
	out = b64From24(0, 0, sum[11], 2, out)
	return string(out)
}

// --- SHA-crypt ($5$/$6$) -----------------------------------------------------

// DefaultRounds is SHA-crypt's own implicit round count, used whenever a
// caller passes rounds == 0 to SHA256Crypt/SHA512Crypt.
const DefaultRounds = 5000

// MinRounds and MaxRounds are Drepper's spec's own clamp bounds: an
// explicitly requested round count outside this range is silently clamped
// to the nearer bound, matching real crypt(3)/libxcrypt exactly.
const (
	MinRounds = 1000
	MaxRounds = 999999999
)

// SHA256Crypt computes SHA-256-crypt ($5$) per Drepper's spec.
//
// rounds == 0 means "unspecified": the algorithm's own DefaultRounds
// (5000) applies internally and the output omits the "rounds=N$" prefix —
// matching real crypt(3), which only prints that prefix when the caller
// explicitly requested a round count. Any other rounds value (even 5000
// given explicitly) is clamped to [MinRounds, MaxRounds] and the clamped
// value is always printed, even if clamping left it at 5000.
func SHA256Crypt(password, salt string, rounds int) string {
	return shaCrypt(password, salt, rounds, false)
}

// SHA512Crypt is SHA256Crypt's sibling for $6$.
func SHA512Crypt(password, salt string, rounds int) string {
	return shaCrypt(password, salt, rounds, true)
}

// clampRounds applies real crypt(3)'s own rounds semantics: requested == 0
// means unspecified (use DefaultRounds, explicit reports false so the
// caller omits the "rounds=" prefix); any other value is clamped into
// [MinRounds, MaxRounds] and explicit reports true, even if clamping left
// the count at DefaultRounds — separated from shaCrypt itself so the clamp
// boundaries are unit-testable without running a real 999999999-round
// hash.
func clampRounds(requested int) (n int, explicit bool) {
	if requested == 0 {
		return DefaultRounds, false
	}
	n = requested
	if n < MinRounds {
		n = MinRounds
	} else if n > MaxRounds {
		n = MaxRounds
	}
	return n, true
}

func shaCrypt(password, salt string, rounds int, is512 bool) string {
	var newHash func() hash.Hash
	var magic string
	var hlen int
	if is512 {
		newHash, magic, hlen = sha512.New, "$6$", 64
	} else {
		newHash, magic, hlen = sha256.New, "$5$", 32
	}

	n, explicit := clampRounds(rounds)

	pw := []byte(password)
	s := []byte(salt)
	if len(s) > 16 {
		s = s[:16]
	}

	b := newHash()
	b.Write(pw)
	b.Write(s)
	b.Write(pw)
	sumB := b.Sum(nil)

	a := newHash()
	a.Write(pw)
	a.Write(s)
	for i := len(pw); i > 0; i -= hlen {
		if i > hlen {
			a.Write(sumB)
		} else {
			a.Write(sumB[:i])
		}
	}
	for i := len(pw); i > 0; i >>= 1 {
		if i&1 == 1 {
			a.Write(sumB)
		} else {
			a.Write(pw)
		}
	}
	sumA := a.Sum(nil)

	dp := newHash()
	for range pw {
		dp.Write(pw)
	}
	p := cryptSeq(dp.Sum(nil), len(pw), hlen)

	ds := newHash()
	for i := 0; i < 16+int(sumA[0]); i++ {
		ds.Write(s)
	}
	sBytes := cryptSeq(ds.Sum(nil), len(s), hlen)

	cur := sumA
	for i := 0; i < n; i++ {
		c := newHash()
		if i&1 == 1 {
			c.Write(p)
		} else {
			c.Write(cur)
		}
		if i%3 != 0 {
			c.Write(sBytes)
		}
		if i%7 != 0 {
			c.Write(p)
		}
		if i&1 == 1 {
			c.Write(cur)
		} else {
			c.Write(p)
		}
		cur = c.Sum(nil)
	}

	out := make([]byte, 0, 132)
	out = append(out, magic...)
	if explicit {
		out = append(out, "rounds="+strconv.Itoa(n)+"$"...)
	}
	out = append(out, s...)
	out = append(out, '$')
	if is512 {
		out = shaEncode512(cur, out)
	} else {
		out = shaEncode256(cur, out)
	}
	return string(out)
}

// cryptSeq builds a length-n byte sequence by repeating the hlen-byte digest.
func cryptSeq(digest []byte, n, hlen int) []byte {
	out := make([]byte, 0, n)
	for i := n; i > 0; i -= hlen {
		if i > hlen {
			out = append(out, digest...)
		} else {
			out = append(out, digest[:i]...)
		}
	}
	return out
}

func shaEncode256(c, out []byte) []byte {
	perm := [][3]int{
		{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23},
		{24, 4, 14}, {15, 25, 5}, {6, 16, 26}, {27, 7, 17},
		{18, 28, 8}, {9, 19, 29},
	}
	for _, p := range perm {
		out = b64From24(c[p[0]], c[p[1]], c[p[2]], 4, out)
	}
	out = b64From24(0, c[31], c[30], 3, out)
	return out
}

func shaEncode512(c, out []byte) []byte {
	perm := [][3]int{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45},
		{25, 46, 4}, {47, 5, 26}, {6, 27, 48}, {28, 49, 7},
		{50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32},
		{12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57},
		{37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19},
		{62, 20, 41},
	}
	for _, p := range perm {
		out = b64From24(c[p[0]], c[p[1]], c[p[2]], 4, out)
	}
	out = b64From24(0, 0, c[63], 2, out)
	return out
}

// --- bcrypt ($2a$/$2b$/$2x$/$2y$) -------------------------------------------

const bcryptB64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var magicCipherData = []byte("OrpheanBeholderScryDoubt")

func bcryptB64Decode(s string) []byte {
	var rev [256]byte
	for i := range rev {
		rev[i] = 0xff
	}
	for i := 0; i < len(bcryptB64); i++ {
		rev[bcryptB64[i]] = byte(i)
	}
	var out []byte
	var buf uint
	bits := 0
	for i := 0; i < len(s); i++ {
		v := rev[s[i]]
		if v == 0xff {
			continue
		}
		buf = buf<<6 | uint(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>uint(bits)))
		}
	}
	return out
}

func bcryptB64Encode(src []byte) []byte {
	var out []byte
	var buf uint
	bits := 0
	for _, b := range src {
		buf = buf<<8 | uint(b)
		bits += 8
		for bits >= 6 {
			bits -= 6
			out = append(out, bcryptB64[(buf>>uint(bits))&0x3f])
		}
	}
	if bits > 0 {
		out = append(out, bcryptB64[(buf<<uint(6-bits))&0x3f])
	}
	return out
}

// Bcrypt computes a crypt(3)-format bcrypt hash: "$<prefix>$<cost>$<22-char
// salt><31-char hash>". prefix selects the variant ("2a", "2b", "2x", or
// "2y" — "2b" is the modern default every current implementation, including
// Ansible's own, uses); cost is the work factor, 4-31; salt must be exactly
// 16 raw bytes (bcrypt's own fixed salt size — RandomSalt is NOT the right
// source here, since bcrypt's salt is raw bytes, not crypt(3)'s usual
// printable charset; use crypto/rand directly).
func Bcrypt(password, prefix string, cost int, salt []byte) (string, error) {
	if len(salt) != 16 {
		return "", fmt.Errorf("unixcrypt: bcrypt salt must be exactly 16 bytes, got %d", len(salt))
	}
	if cost < 4 || cost > 31 {
		return "", fmt.Errorf("unixcrypt: bcrypt cost must be 4-31, got %d", cost)
	}

	// key is password + NUL and is therefore never empty, so
	// NewSaltedCipher (which only errors on a zero-length key) cannot fail
	// here.
	key := append([]byte(password), 0)
	c, err := blowfish.NewSaltedCipher(key, salt)
	if err != nil {
		return "", fmt.Errorf("unixcrypt: %w", err)
	}
	rounds := uint64(1) << uint(cost)
	for i := uint64(0); i < rounds; i++ {
		blowfish.ExpandKey(key, c)
		blowfish.ExpandKey(salt, c)
	}
	cipherData := make([]byte, len(magicCipherData))
	copy(cipherData, magicCipherData)
	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
		}
	}
	hsh := bcryptB64Encode(cipherData[:23])
	saltStr := string(bcryptB64Encode(salt))
	cs := strconv.Itoa(cost)
	if cost < 10 {
		cs = "0" + cs
	}
	return "$" + prefix + "$" + cs + "$" + saltStr + string(hsh), nil
}

// BcryptFromMCF reproduces crypt(3) bcrypt for a caller that already has a
// pre-formed MCF salt of the form "<cost>$<22-char base64>" — the shape
// Puppet's own pw_hash(password, type, salt) function takes as its third
// argument.
func BcryptFromMCF(password, prefix, mcfSalt string) (string, error) {
	if len(mcfSalt) < 25 || mcfSalt[2] != '$' {
		return "", fmt.Errorf("unixcrypt: invalid bcrypt salt %q, want \"<cost>$<22-char-base64>\"", mcfSalt)
	}
	cost, err := strconv.Atoi(mcfSalt[:2])
	if err != nil {
		return "", fmt.Errorf("unixcrypt: invalid bcrypt cost in salt %q", mcfSalt)
	}
	salt22 := mcfSalt[3:25]
	// A 22-character bcrypt-base64 salt always decodes to exactly 16 bytes.
	decoded := bcryptB64Decode(salt22)
	if len(decoded) < 16 {
		return "", fmt.Errorf("unixcrypt: bcrypt salt %q decodes to fewer than 16 bytes", salt22)
	}
	return Bcrypt(password, prefix, cost, decoded[:16])
}
