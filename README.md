<p align="center"><img src="https://raw.githubusercontent.com/go-encryptions/brand/main/social/go-encryptions.png" alt="go-encryptions/unixcrypt" width="720"></p>

# go-encryptions/unixcrypt

[![ci](https://github.com/go-encryptions/unixcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/go-encryptions/unixcrypt/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-encryptions/unixcrypt.svg)](https://pkg.go.dev/github.com/go-encryptions/unixcrypt)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Pure-Go (`CGO_ENABLED=0`) implementation of the crypt(3)/MCF (Modular Crypt
Format) password hash algorithms: **MD5-crypt** (`$1$`, Poul-Henning Kamp's
original FreeBSD algorithm), **SHA-256-crypt**/**SHA-512-crypt** (`$5$`/`$6$`,
per [Ulrich Drepper's specification](https://www.akkadia.org/drepper/SHA-crypt.txt)),
and **bcrypt** (`$2a$`/`$2b$`/`$2x$`/`$2y$`, via the pure-Go blowfish
primitive). No component links against libc's own `crypt(3)` or uses cgo, so
it cross-compiles and produces identical output on every Go target,
including big-endian s390x.

Every algorithm's output was validated against real `openssl passwd` and the
canonical OpenBSD `bcrypt.c` test vectors.

This package was extracted from
[`go-puppet/puppet`](https://github.com/go-puppet/puppet)'s own `pw_hash()`
implementation to be shared, rather than reimplemented, by every consumer
that needs it — currently `go-puppet/puppet` (Puppet's `pw_hash()` stdlib
function) and [`go-ansible/template`](https://github.com/go-ansible/template)
(Ansible's `password_hash` filter).

## Install

```sh
go get github.com/go-encryptions/unixcrypt
```

## API

```go
func MD5Crypt(password, salt string) string
func SHA256Crypt(password, salt string, rounds int) (string, error)
func SHA512Crypt(password, salt string, rounds int) (string, error)
func Bcrypt(password, prefix string, cost int, salt []byte) (string, error)
func BcryptStrict(password, prefix string, cost int, salt []byte) (string, error)
func BcryptFromMCF(password, prefix, mcfSalt string) (string, error)

func RandomSalt(n int) (string, error)
func ValidSaltChars(s string) bool

const DefaultRounds = 5000
const MinRounds = 1000
const MaxRounds = 999999999
const MaxPasswordLen = 511

var ErrPasswordTooLong error
```

- **Password length cap (SHA-crypt).** SHA-crypt's cost is quadratic in the
  password length, so `SHA256Crypt`/`SHA512Crypt` return `ErrPasswordTooLong`
  for a password above `MaxPasswordLen` (511 bytes; libxcrypt's
  `CRYPT_MAX_PASSPHRASE_SIZE` is 512 counting the terminating NUL) instead of
  burning CPU or truncating. Callers that take `rounds` (up to `MaxRounds`) or
  a bcrypt cost (up to 31) from untrusted input should apply their own policy
  cap first: those bounds are caller-controlled CPU by design.

- `MD5Crypt`/`SHA256Crypt`/`SHA512Crypt` take a plain salt string and return
  the full `$id$salt$hash` (or, for SHA-crypt with an explicit round count,
  `$id$rounds=N$salt$hash`) MCF string.
- `SHA256Crypt`/`SHA512Crypt`'s `rounds` parameter matches real crypt(3)
  exactly: `0` means "unspecified" — the algorithm's own default of 5000
  applies internally and the output omits the `rounds=` prefix entirely.
  Any other value (even `5000` given explicitly) is clamped into
  `[MinRounds, MaxRounds]` and the clamped value is always printed, even if
  clamping left it at 5000 — a caller that explicitly asked for 5000 rounds
  gets a *different string* than one that didn't specify rounds at all,
  even though the digest itself is identical either way. This distinction
  is real crypt(3) behavior, confirmed against `openssl passwd`, not an
  invented convenience.
- `Bcrypt` accepts only the prefixes `2a`, `2b`, `2x` and `2y` (any other
  prefix is an error) and a cost of 4-31; `BcryptFromMCF` requires the cost
  to be exactly two ASCII digits (`"+4"` and `" 4"` are refused). Both
  formerly built a malformed MCF string on request.
- `$2x$` reproduces openwall crypt_blowfish's sign-extension bug (a password
  byte >= 0x80 sign-extends into its key word), so legacy hashes made by
  affected pre-2011 implementations verify; it matches the `wrapper.c` vector
  for `"\xa3"`. For passwords without such bytes it equals `$2y$`. `$2x$` is
  for verifying old hashes only: never use it to create new ones. `$2a$`,
  `$2b$` and `$2y$` use the corrected algorithm (crypt_blowfish's extra `$2a$`
  safety measure for some `\xff` passwords is not implemented).
- **bcrypt reads only the first 72 bytes of the password** (bcrypt's own
  limit): `Bcrypt` silently ignores the rest, so two passwords sharing their
  first 72 bytes hash equally. The default is unchanged for compatibility;
  `BcryptStrict` returns `ErrPasswordTooLong` above `BcryptMaxPasswordLen`
  (72) bytes instead. A NUL byte inside a bcrypt password does not end it,
  unlike C `crypt(3)`, which stops at the first NUL.
- `Bcrypt` takes a raw 16-byte salt directly; `BcryptFromMCF` is a
  convenience for a caller that already has a pre-formed
  `"<cost>$<22-char-base64>"` salt (the shape Puppet's own
  `pw_hash(password, type, salt)` takes as its third argument).
- `RandomSalt` generates a cryptographically random salt from crypt(3)'s own
  accepted charset (`[A-Za-z0-9./]`) via `crypto/rand` — **not** appropriate
  for bcrypt, whose salt is raw bytes rather than that printable charset;
  use `crypto/rand.Read` directly for a bcrypt salt.

## Example

```go
package main

import (
	"fmt"

	"github.com/go-encryptions/unixcrypt"
)

func main() {
	salt, _ := unixcrypt.RandomSalt(16)
	h, _ := unixcrypt.SHA512Crypt("hunter2", salt, 0) // real crypt(3) default: 5000 rounds, no prefix
	fmt.Println(h)
	h, _ = unixcrypt.SHA512Crypt("hunter2", salt, 100000) // $6$rounds=100000$...
	fmt.Println(h)
}
```

## Scope

Deliberately narrow: the four crypt(3)/MCF formats above, nothing else.
`apr1` (Apache's own MD5-crypt variant, `$apr1$` instead of `$1$` — same
algorithm, different magic string) is not implemented, since neither current
consumer needs it; it would be a one-line addition (`MD5Crypt` already takes
its magic string as an internal constant) if a future consumer does.
