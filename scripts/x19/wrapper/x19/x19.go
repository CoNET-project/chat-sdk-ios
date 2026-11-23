// Package x19 is the binding surface for the X-19 audit: encrypt, decrypt, detached sign and
// detached verify with gopenpgp v3.5.2. gopenpgp/mime is not imported. Built with gomobile bind for iOS, so that the
// linked product can be inspected (net/http, WebSocket, net.Dial, Listen, socket).
package x19

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"golang.org/x/crypto/argon2"
)

// EncryptArmored encrypts plain to the recipient's public key and returns the ASCII armor.
func EncryptArmored(pubArmor string, plain []byte) (string, error) {
	pub, err := crypto.NewKeyFromArmored(pubArmor)
	if err != nil {
		return "", err
	}
	h, err := crypto.PGP().Encryption().Recipient(pub).New()
	if err != nil {
		return "", err
	}
	m, err := h.Encrypt(plain)
	if err != nil {
		return "", err
	}
	return m.Armor()
}

// DecryptArmored decrypts an ASCII-armored message with the private key and returns the plain text.
func DecryptArmored(privArmor string, cipher string) (string, error) {
	priv, err := crypto.NewKeyFromArmored(privArmor)
	if err != nil {
		return "", err
	}
	h, err := crypto.PGP().Decryption().DecryptionKey(priv).New()
	if err != nil {
		return "", err
	}
	r, err := h.Decrypt([]byte(cipher), crypto.Armor)
	if err != nil {
		return "", err
	}
	return r.String(), nil
}

// DecryptArmoredText decrypts like DecryptArmored, and applies the literal-format rules of spec 25.34.2 step 6 and
// 25.32 (2026). A text literal (format t or u) comes back with CRLF turned into LF; a lone CR is kept.
// A binary literal (format b) comes back unchanged, and only when it is valid UTF-8; otherwise the error is "not_utf8".
// The literal format is read from the literal data packet, not guessed from the content.
func DecryptArmoredText(privArmor string, cipher string) (string, error) {
	priv, err := crypto.NewKeyFromArmored(privArmor)
	if err != nil {
		return "", err
	}
	h, err := crypto.PGP().Decryption().DecryptionKey(priv).New()
	if err != nil {
		return "", err
	}
	r, err := h.Decrypt([]byte(cipher), crypto.Armor)
	if err != nil {
		return "", err
	}
	data := r.Bytes()
	if md := r.Metadata(); md != nil && md.IsUtf8() {
		return strings.ReplaceAll(string(data), "\r\n", "\n"), nil
	}
	if !utf8.Valid(data) {
		return "", errors.New("not_utf8")
	}
	return string(data), nil
}

// GenerateArmoredKey makes a new OpenPGP key in memory and returns its private key armor. The key is the PWA's convention
// (chat.ts generatePgpKey): version 4, curve25519 (legacy: EdDSA primary, ECDH subkey), user ID = name, no passphrase.
// 2026-11-13: approved for pgpIdentityCreate, which generates only after the user confirms natively (25.30.5, 25.30.11).
func GenerateArmoredKey(name string) (string, error) {
	key, err := crypto.PGP().KeyGeneration().AddUserId(name, "").OverrideProfileAlgorithm(crypto.KeyGenerationCurve25519Legacy).New().GenerateKey()
	if err != nil {
		return "", err
	}
	return key.Armor()
}

// PublicArmor returns the public key armor of an armored private key (the public part only).
func PublicArmor(privArmor string) (string, error) {
	priv, err := crypto.NewKeyFromArmored(privArmor)
	if err != nil {
		return "", err
	}
	pub, err := priv.ToPublic()
	if err != nil {
		return "", err
	}
	return pub.Armor()
}

// SignDetached returns a detached, ASCII-armored signature over data.
func SignDetached(privArmor string, data []byte) (string, error) {
	priv, err := crypto.NewKeyFromArmored(privArmor)
	if err != nil {
		return "", err
	}
	h, err := crypto.PGP().Sign().SigningKey(priv).Detached().New()
	if err != nil {
		return "", err
	}
	sig, err := h.Sign(data, crypto.Armor)
	if err != nil {
		return "", err
	}
	return string(sig), nil
}

// VerifyDetached reports whether sigArmor is a valid detached signature over data for the public key.
func VerifyDetached(pubArmor string, data []byte, sigArmor string) (bool, error) {
	pub, err := crypto.NewKeyFromArmored(pubArmor)
	if err != nil {
		return false, err
	}
	h, err := crypto.PGP().Verify().VerificationKey(pub).New()
	if err != nil {
		return false, err
	}
	r, err := h.VerifyDetached(data, []byte(sigArmor), crypto.Armor)
	if err != nil {
		return false, err
	}
	return r.SignatureError() == nil, nil
}

// PrimaryFingerprint returns the v4 primary key fingerprint (uppercase hex) of an armored PGP key (25.16, P-IMP-PGP).
func PrimaryFingerprint(armor string) (string, error) {
	key, err := crypto.NewKeyFromArmored(armor)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(key.GetFingerprint()), nil
}

// FirstSubkeyKeyID returns the key ID of the first subkey (uppercase, 16 hex digits): getKeyIDs()[1] (PWA chat.ts:43).
func FirstSubkeyKeyID(armor string) (string, error) {
	key, err := crypto.NewKeyFromArmored(armor)
	if err != nil {
		return "", err
	}
	entity := key.GetEntity()
	if entity == nil || len(entity.Subkeys) == 0 {
		return "", errors.New("no subkey")
	}
	return fmt.Sprintf("%016X", entity.Subkeys[0].PublicKey.KeyId), nil
}

// Argon2IDKey derives keyLen bytes with Argon2id, version 0x13 (v = 19): the KDF of the recovery record (spec 25.42.5 step 6,
// PWA deriveAesKeyFromPassword). The parameters come from the record's `stored` field, which is untrusted chain data, so they
// are bounded here: memory 8 MiB to 256 MiB, 1 to 10 passes, 1 to 4 lanes, a 32-byte key, a salt of 8 to 64 bytes.
// 2026-11-13 approved Argon2id through this wrapper (golang.org/x/crypto/argon2, already a requirement of the module).
func Argon2IDKey(password []byte, salt []byte, memoryKB int, iterations int, parallelism int, keyLen int) ([]byte, error) {
	if memoryKB < 8*1024 || memoryKB > 256*1024 {
		return nil, errors.New("argon2_memory_out_of_range")
	}
	if iterations < 1 || iterations > 10 {
		return nil, errors.New("argon2_time_out_of_range")
	}
	if parallelism < 1 || parallelism > 4 {
		return nil, errors.New("argon2_lanes_out_of_range")
	}
	if keyLen != 32 {
		return nil, errors.New("argon2_key_length")
	}
	if len(salt) < 8 || len(salt) > 64 {
		return nil, errors.New("argon2_salt_length")
	}
	return argon2.IDKey(password, salt, uint32(iterations), uint32(memoryKB), uint8(parallelism), uint32(keyLen)), nil
}
