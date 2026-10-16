package pastevault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// PVWRAP1 (spec §3.2) wraps a 32-byte content key to an X25519 public key:
//
//	e_sk ← random(32); e_pk = X25519(e_sk, 9)
//	ss   = X25519(e_sk, R_pk)             (abort if all zero)
//	wk   = HKDF-SHA256(ikm=ss, salt=e_pk||R_pk, info="pastevault:wrap:v1", L=32)
//	n    ← random(24)
//	aad  = "pastevault:wrap:v1:" + context + ":" + fingerprint(R_pk)
//	ct   = XChaCha20-Poly1305(wk, n).Seal(K, aad)           (48 bytes)
//	envelope = 0x01 || e_pk || n || ct                       (105 bytes, base64url)
//
// The context names what the key unlocks (paste:<slug>, file-share:<slug>,
// request:<id>, store:<NAME>), so an envelope can't be moved to another
// share. The recipient fingerprint is always computed from the public key.
// frontend/src/lib/wrap.ts implements the same construction; both are checked
// against testdata/crypto/vectors.json.
const (
	X25519KeySize    = 32
	ContentKeySize   = chacha20poly1305.KeySize
	WrapEnvelopeSize = 1 + X25519KeySize + chacha20poly1305.NonceSizeX + ContentKeySize + chacha20poly1305.Overhead

	wrapVersion   byte = 0x01
	wrapInfo           = "pastevault:wrap:v1"
	wrapAADPrefix      = "pastevault:wrap:v1:"
)

var (
	// ErrLowOrderKey means a public key is not usable for X25519: the shared
	// secret would be all zero (a low-order point), so nothing would be secret.
	ErrLowOrderKey = errors.New("the X25519 public key is a low-order point")
	// ErrUnwrapFailed covers every way an envelope can fail to open: wrong
	// recipient key, wrong context, tampering. They are deliberately not
	// told apart.
	ErrUnwrapFailed = errors.New("the wrapped key could not be opened")
)

// Wrap contexts. Each names exactly one object, so an envelope only ever
// unlocks the thing it was made for.
func PasteWrapContext(slug string) string     { return "paste:" + slug }
func FileShareWrapContext(slug string) string { return "file-share:" + slug }
func RequestWrapContext(id string) string     { return "request:" + id }
func StoreWrapContext(name string) string     { return "store:" + name }

// AgentKeyPair is an X25519 key pair with its fingerprint.
type AgentKeyPair struct {
	PrivateKey  []byte
	PublicKey   []byte
	Fingerprint string
}

// GenerateAgentKeyPair creates a fresh X25519 key pair.
func GenerateAgentKeyPair() (AgentKeyPair, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return AgentKeyPair{}, err
	}

	return AgentKeyPairFromPrivate(privateKey.Bytes())
}

// AgentKeyPairFromPrivate derives the public key and fingerprint of a 32-byte
// X25519 private key.
func AgentKeyPairFromPrivate(privateKeyBytes []byte) (AgentKeyPair, error) {
	privateKey, err := ecdh.X25519().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return AgentKeyPair{}, fmt.Errorf("invalid X25519 private key: %w", err)
	}

	publicKey := privateKey.PublicKey().Bytes()
	return AgentKeyPair{
		PrivateKey:  bytes.Clone(privateKeyBytes),
		PublicKey:   publicKey,
		Fingerprint: Fingerprint(publicKey),
	}, nil
}

// DecodeAgentPublicKey decodes a base64url public key and rejects anything
// that is not a usable 32-byte X25519 key (including low-order points).
func DecodeAgentPublicKey(value string) ([]byte, error) {
	publicKey, err := DecodeBase64URL(value)
	if err != nil || len(publicKey) != X25519KeySize {
		return nil, fmt.Errorf("a public key must be %d bytes of unpadded base64url", X25519KeySize)
	}
	if err := checkUsablePublicKey(publicKey); err != nil {
		return nil, err
	}

	return publicKey, nil
}

// DecodeAgentPrivateKey decodes a base64url X25519 private key.
func DecodeAgentPrivateKey(value string) (AgentKeyPair, error) {
	privateKey, err := DecodeBase64URL(value)
	if err != nil || len(privateKey) != X25519KeySize {
		return AgentKeyPair{}, fmt.Errorf("a private key must be %d bytes of unpadded base64url", X25519KeySize)
	}

	return AgentKeyPairFromPrivate(privateKey)
}

// checkUsablePublicKey runs a throwaway exchange: crypto/ecdh rejects
// low-order points by refusing an all-zero shared secret.
func checkUsablePublicKey(publicKey []byte) error {
	probe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	_, err = x25519SharedSecret(probe, publicKey)
	return err
}

func x25519SharedSecret(privateKey *ecdh.PrivateKey, publicKeyBytes []byte) ([]byte, error) {
	if len(publicKeyBytes) != X25519KeySize {
		return nil, fmt.Errorf("a public key must be %d bytes", X25519KeySize)
	}
	publicKey, err := ecdh.X25519().NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, ErrLowOrderKey
	}

	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, ErrLowOrderKey
	}
	// crypto/ecdh already refuses an all-zero result; checked again because
	// a zero secret would make the wrap key public.
	if subtle.ConstantTimeCompare(shared, make([]byte, len(shared))) == 1 {
		return nil, ErrLowOrderKey
	}

	return shared, nil
}

func wrapKeyAndAAD(sharedSecret, ephemeralPublic, recipientPublic []byte, context string) ([]byte, []byte, error) {
	salt := make([]byte, 0, 2*X25519KeySize)
	salt = append(salt, ephemeralPublic...)
	salt = append(salt, recipientPublic...)

	wrapKey, err := hkdf.Key(sha256.New, sharedSecret, salt, wrapInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}

	aad := []byte(wrapAADPrefix + context + ":" + Fingerprint(recipientPublic))
	return wrapKey, aad, nil
}

// WrapKey seals contentKey to recipientPublicKey for context and returns the
// base64url PVWRAP1 envelope.
func WrapKey(contentKey, recipientPublicKey []byte, context string) (string, error) {
	ephemeral, err := randomBytes(X25519KeySize)
	if err != nil {
		return "", err
	}
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return "", err
	}

	return wrapKeyWith(contentKey, recipientPublicKey, context, ephemeral, nonce)
}

// wrapKeyWith is WrapKey with caller-supplied randomness (test vectors).
func wrapKeyWith(contentKey, recipientPublicKey []byte, context string, ephemeralPrivate, nonce []byte) (string, error) {
	if len(contentKey) != ContentKeySize {
		return "", fmt.Errorf("the content key must be %d bytes", ContentKeySize)
	}
	if context == "" {
		return "", errors.New("a wrap context is required")
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return "", fmt.Errorf("the nonce must be %d bytes", chacha20poly1305.NonceSizeX)
	}

	ephemeral, err := ecdh.X25519().NewPrivateKey(ephemeralPrivate)
	if err != nil {
		return "", fmt.Errorf("invalid ephemeral key: %w", err)
	}
	sharedSecret, err := x25519SharedSecret(ephemeral, recipientPublicKey)
	if err != nil {
		return "", err
	}

	ephemeralPublic := ephemeral.PublicKey().Bytes()
	wrapKey, aad, err := wrapKeyAndAAD(sharedSecret, ephemeralPublic, recipientPublicKey, context)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return "", err
	}

	envelope := make([]byte, 0, WrapEnvelopeSize)
	envelope = append(envelope, wrapVersion)
	envelope = append(envelope, ephemeralPublic...)
	envelope = append(envelope, nonce...)
	envelope = aead.Seal(envelope, nonce, contentKey, aad)

	return EncodeBase64URL(envelope), nil
}

// UnwrapKey opens a PVWRAP1 envelope with the recipient's private key. The
// recipient's fingerprint in the AAD is computed from its own public key, so
// an envelope made for another key or another context fails.
func UnwrapKey(envelope string, recipientPrivateKey []byte, context string) ([]byte, error) {
	data, err := DecodeBase64URL(envelope)
	if err != nil || len(data) != WrapEnvelopeSize || data[0] != wrapVersion {
		return nil, ErrUnwrapFailed
	}
	if context == "" {
		return nil, errors.New("a wrap context is required")
	}

	recipient, err := ecdh.X25519().NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 private key: %w", err)
	}

	ephemeralPublic := data[1 : 1+X25519KeySize]
	nonce := data[1+X25519KeySize : 1+X25519KeySize+chacha20poly1305.NonceSizeX]
	ciphertext := data[1+X25519KeySize+chacha20poly1305.NonceSizeX:]

	sharedSecret, err := x25519SharedSecret(recipient, ephemeralPublic)
	if err != nil {
		return nil, ErrUnwrapFailed
	}

	wrapKey, aad, err := wrapKeyAndAAD(sharedSecret, ephemeralPublic, recipient.PublicKey().Bytes(), context)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, err
	}

	contentKey, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrUnwrapFailed
	}

	return contentKey, nil
}
