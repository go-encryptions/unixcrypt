package unixcrypt

import (
	"testing"

	xbcrypt "golang.org/x/crypto/bcrypt"
)

// TestBcryptPrefixAndCost is the regression test for an unvalidated prefix and
// a signed cost: Bcrypt("pw", "6$rounds=1000$x", 4, salt) used to return a
// string starting "$6$rounds=1000$x$04$", and BcryptFromMCF with the cost "+4"
// used to succeed because strconv.Atoi accepts a sign.
func TestBcryptPrefixAndCost(t *testing.T) {
	salt := make([]byte, 16)
	for _, prefix := range []string{"6$rounds=1000$x", "", "2", "2c", "2A", "$2b", "2b$", "1", "2 b"} {
		if h, err := Bcrypt("pw", prefix, 4, salt); err == nil {
			t.Errorf("Bcrypt prefix %q accepted: %s", prefix, h)
		}
	}
	for _, mcf := range []string{"+4$......................", "-4$......................", " 4$......................", "4 $......................", "0x$......................"} {
		if h, err := BcryptFromMCF("pw", "2b", mcf); err == nil {
			t.Errorf("BcryptFromMCF cost field of %q accepted: %s", mcf, h)
		}
	}
}

// TestBcryptPrefixesAccepted checks every accepted prefix, and the lowest
// cost, against golang.org/x/crypto/bcrypt, which verifies the result as a
// "$2a$"-style hash once the prefix is normalised.
func TestBcryptPrefixesAccepted(t *testing.T) {
	salt := []byte("0123456789abcdef")
	for _, prefix := range []string{"2a", "2b", "2x", "2y"} {
		h, err := Bcrypt("password", prefix, 4, salt)
		if err != nil {
			t.Errorf("Bcrypt prefix %q: %v", prefix, err)
			continue
		}
		if want := "$" + prefix + "$04$"; h[:len(want)] != want {
			t.Errorf("Bcrypt prefix %q = %q, want the %q header", prefix, h, want)
		}
	}
	h, err := Bcrypt("password", "2b", 4, salt)
	if err != nil {
		t.Fatal(err)
	}
	if err := xbcrypt.CompareHashAndPassword([]byte(h), []byte("password")); err != nil {
		t.Errorf("x/crypto/bcrypt rejects %q: %v", h, err)
	}
}

// TestBcryptFromMCFTwoDigitCost keeps the valid two-digit forms working.
func TestBcryptFromMCFTwoDigitCost(t *testing.T) {
	h, err := BcryptFromMCF("password", "2b", "04$......................")
	if err != nil {
		t.Fatal(err)
	}
	if h[:7] != "$2b$04$" {
		t.Errorf("BcryptFromMCF = %q, want the $2b$04$ header", h)
	}
}

// TestBcryptCostLowerBound pins cost 4 (the lowest accepted); a cost of 3 is
// refused in TestBcryptErrors.
func TestBcryptCostLowerBound(t *testing.T) {
	if _, err := Bcrypt("password", "2b", 4, make([]byte, 16)); err != nil {
		t.Errorf("Bcrypt cost 4: %v", err)
	}
}
