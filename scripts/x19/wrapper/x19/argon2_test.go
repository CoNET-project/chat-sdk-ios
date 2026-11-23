package x19

import (
	"bytes"
	"testing"
)

// Argon2IDKey is a deterministic wrapper over x/crypto/argon2 (v19). Known-answer checks against the PWA output are in the
// Swift vector tests (native-recovery-vectors.v1.json); here only the bounds and the determinism are checked.
func TestArgon2IDKeyDeterministicAndBounded(t *testing.T) {
	pw := []byte("synthetic-password")
	salt := []byte("synthetic-salt-16")
	a, err := Argon2IDKey(pw, salt, 8*1024, 1, 1, 32)
	if err != nil || len(a) != 32 {
		t.Fatalf("derive failed: %v len=%d", err, len(a))
	}
	b, _ := Argon2IDKey(pw, salt, 8*1024, 1, 1, 32)
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	c, _ := Argon2IDKey([]byte("other"), salt, 8*1024, 1, 1, 32)
	if bytes.Equal(a, c) {
		t.Fatal("password does not change the key")
	}
	bad := []struct {
		name string
		f    func() error
	}{
		{"memory low", func() error { _, e := Argon2IDKey(pw, salt, 1024, 1, 1, 32); return e }},
		{"memory high", func() error { _, e := Argon2IDKey(pw, salt, 512*1024, 1, 1, 32); return e }},
		{"time zero", func() error { _, e := Argon2IDKey(pw, salt, 8*1024, 0, 1, 32); return e }},
		{"lanes high", func() error { _, e := Argon2IDKey(pw, salt, 8*1024, 1, 5, 32); return e }},
		{"key length", func() error { _, e := Argon2IDKey(pw, salt, 8*1024, 1, 1, 16); return e }},
		{"salt short", func() error { _, e := Argon2IDKey(pw, []byte("short"), 8*1024, 1, 1, 32); return e }},
	}
	for _, tc := range bad {
		if tc.f() == nil {
			t.Fatalf("%s: expected refusal", tc.name)
		}
	}
}
