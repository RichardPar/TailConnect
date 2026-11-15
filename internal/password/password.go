// Package password hashes and verifies account passwords with argon2id.
//
// Hashes are stored in the PHC string format:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//
// The parameters are OWASP's recommended minimum for argon2id. They are
// recorded in each hash, so they can be raised later without invalidating
// existing passwords.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MinLength = 10
	MaxLength = 256

	argonMemory  = 19 * 1024 // KiB
	argonTime    = 2
	argonThreads = 1
	keyLen       = 32
	saltLen      = 16
)

var b64 = base64.RawStdEncoding

// Check reports whether pw is acceptable as a new password.
func Check(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinLength {
		return fmt.Errorf("password must be at least %d characters", MinLength)
	}
	if len(pw) > MaxLength {
		return fmt.Errorf("password must be at most %d bytes", MaxLength)
	}
	return nil
}

// Hash returns the encoded argon2id hash of pw.
func Hash(pw string) (string, error) {
	if err := Check(pw); err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errFormat = errors.New("password: unrecognised hash format")

// Verify reports whether pw matches the encoded hash. An empty or malformed
// hash never matches.
func Verify(pw, encoded string) bool {
	ok, _ := verify(pw, encoded)
	return ok
}

func verify(pw, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || len(pw) > MaxLength {
		return false, errFormat
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, errFormat
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 1<<20 || t > 10 {
		return false, errFormat
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errFormat
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errFormat
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummy is a valid hash that matches no password: verifying against it when
// an account doesn't exist makes failed logins take the same time either way.
var dummy = func() string {
	h, _ := Hash("not-a-real-password-" + strings.Repeat("x", 8))
	return h
}()

// VerifyDummy spends the same effort as Verify, for unknown accounts.
func VerifyDummy(pw string) { Verify(pw, dummy) }
