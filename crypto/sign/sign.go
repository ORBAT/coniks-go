// Package sign implements a digital signature scheme using the Edwards
// form of Curve25519.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
)

const (
	// PrivateKeySize is the size of the private-key in bytes.
	PrivateKeySize = 64
	// PublicKeySize is the size of the public-key in bytes.
	PublicKeySize = 32
	// SignatureSize is the size of the created signature in bytes.
	SignatureSize = 64
)

// PrivateKey wraps the underlying private-key (ed25519.PrivateKey).
// It provides some wrapper methods: Sign(), Public()
type PrivateKey ed25519.PrivateKey

// PublicKey wraps the underlying public-key type. It can be used to verify a
// signature which was created by using a corresponding PrivateKey
type PublicKey ed25519.PublicKey

// GenerateKey generates and returns a fresh random private-key, from
// which the corresponding public-key can be derived (by calling Public()
// on it).
// It will use the passed io.Reader rnd as a source of randomness, or, if
// rnd is nil it will use a sane default (rand.Reader).
//
// It returns an error if the key couldn't be properly generated. This, for
// example, can happen if there isn't enough entropy for the randomness.
func GenerateKey(rnd io.Reader) (PrivateKey, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	_, sk, err := ed25519.GenerateKey(rnd)
	return PrivateKey(sk), err
}

// Sign returns a signature on the passed byte slice message using the
// underlying private-key.
// The passed slice won't be modified.
func (key PrivateKey) Sign(message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(key), message)
}

// Public returns the corresponding public key for the private key.
func (key PrivateKey) Public() PublicKey {
	pk := ed25519.PrivateKey(key).Public()
	return PublicKey(pk.(ed25519.PublicKey))
}

// Verify verifies a signature sig on message using the underlying
// public-key. It returns true if and only if the signature is valid.
// The passed slices aren't modified.
func (pk PublicKey) Verify(message, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pk), message, sig)
}
