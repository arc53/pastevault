package pastevault

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// Agent key fingerprints (spec §3.1):
//
//	digest = SHA-256("pastevault:agent-key:v1" || 0x00 || public_key[32])
//	fp     = "pvk1_" + base32_lower_nopad(digest[0:20])
//
// Clients always compute fingerprints from public keys themselves and never
// trust a fingerprint string sent by the server. Comparisons use the full
// string.
const (
	FingerprintPrefix = "pvk1_"
	// FingerprintLength is the full length, prefix included.
	FingerprintLength = len(FingerprintPrefix) + 32
	// ShortFingerprintChars is how many characters after the prefix the
	// short form shows, and the minimum length of a --to prefix.
	ShortFingerprintChars = 8

	fingerprintDomain = "pastevault:agent-key:v1"
)

var fingerprintEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Fingerprint returns the pvk1_ fingerprint of a 32-byte X25519 public key.
func Fingerprint(publicKey []byte) string {
	hash := sha256.New()
	hash.Write([]byte(fingerprintDomain))
	hash.Write([]byte{0})
	hash.Write(publicKey)
	digest := hash.Sum(nil)

	return FingerprintPrefix + strings.ToLower(fingerprintEncoding.EncodeToString(digest[:20]))
}

// IsFingerprint reports whether value is a complete, well-formed fingerprint.
func IsFingerprint(value string) bool {
	if len(value) != FingerprintLength || !strings.HasPrefix(value, FingerprintPrefix) {
		return false
	}

	return isFingerprintBody(value[len(FingerprintPrefix):])
}

// IsFingerprintPrefix reports whether value is pvk1_ followed by at least
// ShortFingerprintChars (and at most 32) fingerprint characters.
func IsFingerprintPrefix(value string) bool {
	body, found := strings.CutPrefix(value, FingerprintPrefix)
	return found && len(body) >= ShortFingerprintChars && len(body) <= 32 && isFingerprintBody(body)
}

func isFingerprintBody(body string) bool {
	for _, r := range body {
		if !(r >= 'a' && r <= 'z') && !(r >= '2' && r <= '7') {
			return false
		}
	}

	return true
}

// ShortFingerprint is the first ShortFingerprintChars characters after the
// prefix, e.g. "pvk1_abcd2345". It is for display only, never for matching.
func ShortFingerprint(fingerprint string) string {
	body, found := strings.CutPrefix(fingerprint, FingerprintPrefix)
	if !found || len(body) < ShortFingerprintChars {
		return fingerprint
	}

	return FingerprintPrefix + body[:ShortFingerprintChars]
}

// FormatFingerprint groups the fingerprint in blocks of four characters for
// reading aloud or comparing by eye: "pvk1_abcd 2345 …".
func FormatFingerprint(fingerprint string) string {
	body, found := strings.CutPrefix(fingerprint, FingerprintPrefix)
	if !found {
		return fingerprint
	}

	groups := make([]string, 0, (len(body)+3)/4)
	for len(body) > 4 {
		groups = append(groups, body[:4])
		body = body[4:]
	}
	groups = append(groups, body)

	return FingerprintPrefix + strings.Join(groups, " ")
}
