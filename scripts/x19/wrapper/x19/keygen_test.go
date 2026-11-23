package x19

import (
	"strings"
	"testing"
)

// GenerateArmoredKey and PublicArmor (2026). Keys are generated here; nothing is stored.
func TestGenerateArmoredKeyMakesAUsableV4Key(t *testing.T) {
	priv, err := GenerateArmoredKey("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(priv, "-----BEGIN PGP PRIVATE KEY BLOCK-----") {
		t.Fatalf("not a private key armor")
	}
	pub, err := PublicArmor(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pub, "-----BEGIN PGP PUBLIC KEY BLOCK-----") || strings.Contains(pub, "PRIVATE") {
		t.Fatalf("public armor must hold no secret")
	}
	fpPriv, err := PrimaryFingerprint(priv)
	if err != nil {
		t.Fatal(err)
	}
	fpPub, err := PrimaryFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if fpPriv != fpPub {
		t.Fatalf("public and private armor disagree on the fingerprint")
	}
	if len(fpPriv) != 40 {
		t.Fatalf("expected a v4 fingerprint (40 hex digits), got %d", len(fpPriv))
	}
	sub, err := FirstSubkeyKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) != 16 {
		t.Fatalf("subkey key id must be 16 hex digits, got %q", sub)
	}
	cipher, err := EncryptArmored(pub, []byte("round trip"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptArmored(priv, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "round trip" {
		t.Fatalf("round trip failed: %q", plain)
	}
}

func TestGenerateArmoredKeyGivesADifferentKeyEachTime(t *testing.T) {
	a, err := GenerateArmoredKey("same name")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateArmoredKey("same name")
	if err != nil {
		t.Fatal(err)
	}
	fa, _ := PrimaryFingerprint(a)
	fb, _ := PrimaryFingerprint(b)
	if fa == fb {
		t.Fatalf("two generations gave the same fingerprint")
	}
}
