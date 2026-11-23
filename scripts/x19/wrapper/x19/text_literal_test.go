package x19

import (
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// DecryptArmoredText (spec 25.34.2 step 6, 25.32): text literals (t, u) get CRLF to LF, a lone CR is kept; binary
// literals (b) are returned unchanged when valid UTF-8, and refused with "not_utf8" otherwise. Synthetic key, made here.
func textLiteralKeys(t *testing.T) (pubArmor, privArmor string) {
	t.Helper()
	key, err := crypto.PGP().KeyGeneration().AddUserId("synthetic literal", "literal@synthetic.invalid").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	if pubArmor, err = pub.Armor(); err != nil {
		t.Fatal(err)
	}
	if privArmor, err = key.Armor(); err != nil {
		t.Fatal(err)
	}
	return pubArmor, privArmor
}

// encryptLiteral encrypts with a text literal (text=true, the Utf8 option) or a binary literal (text=false).
func encryptLiteral(t *testing.T, pubArmor string, plain []byte, text bool) string {
	t.Helper()
	pub, err := crypto.NewKeyFromArmored(pubArmor)
	if err != nil {
		t.Fatal(err)
	}
	b := crypto.PGP().Encryption().Recipient(pub)
	if text {
		b = b.Utf8()
	}
	h, err := b.New()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := h.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	armored, err := msg.Armor()
	if err != nil {
		t.Fatal(err)
	}
	return armored
}

func TestDecryptArmoredTextTextLiteralCRLFBecomesLF(t *testing.T) {
	pubArmor, privArmor := textLiteralKeys(t)
	armored := encryptLiteral(t, pubArmor, []byte("line one\r\nline two\r\n"), true)
	got, err := DecryptArmoredText(privArmor, armored)
	if err != nil {
		t.Fatal(err)
	}
	if got != "line one\nline two\n" {
		t.Fatalf("text literal: got %q", got)
	}
}

func TestDecryptArmoredTextALoneCRIsKept(t *testing.T) {
	pubArmor, privArmor := textLiteralKeys(t)
	armored := encryptLiteral(t, pubArmor, []byte("a\rb\r\nc"), true)
	got, err := DecryptArmoredText(privArmor, armored)
	if err != nil {
		t.Fatal(err)
	}
	if got != "a\rb\nc" {
		t.Fatalf("lone CR: got %q", got)
	}
}

func TestDecryptArmoredTextBinaryLiteralIsUnchangedWhenUTF8(t *testing.T) {
	pubArmor, privArmor := textLiteralKeys(t)
	plain := "x\r\ny 中文"
	armored := encryptLiteral(t, pubArmor, []byte(plain), false)
	got, err := DecryptArmoredText(privArmor, armored)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("binary literal must not change: got %q", got)
	}
}

func TestDecryptArmoredTextBinaryLiteralNotUTF8IsRefused(t *testing.T) {
	pubArmor, privArmor := textLiteralKeys(t)
	armored := encryptLiteral(t, pubArmor, []byte{0xff, 0xfe, 0x00}, false)
	_, err := DecryptArmoredText(privArmor, armored)
	if err == nil || !strings.Contains(err.Error(), "not_utf8") {
		t.Fatalf("binary literal that is not UTF-8 must fail with not_utf8, got %v", err)
	}
}
