package crypto

import (
	"bytes"

	"github.com/ORBAT/cloniks/crypto/sign"
	"github.com/ORBAT/cloniks/crypto/vrf"
)

// NewStaticTestVRFKey returns a static VRF private key for _tests_.
func NewStaticTestVRFKey() vrf.PrivateKey {
	sk, err := vrf.GenerateKey(bytes.NewReader(
		[]byte("deterministic tests need 256 bit")))
	if err != nil {
		panic(err)
	}
	return sk
}

// NewStaticTestSigningKey returns a static private signing key for _tests_.
func NewStaticTestSigningKey() sign.PrivateKey {
	sk, err := sign.GenerateKey(bytes.NewReader(
		[]byte("deterministic tests need 256 bit")))
	if err != nil {
		panic(err)
	}
	return sk
}
