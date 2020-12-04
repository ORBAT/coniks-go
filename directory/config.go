package directory

import (
	"github.com/ORBAT/cloniks/crypto/hashed"
	"github.com/ORBAT/cloniks/crypto/vrf"
	"github.com/ORBAT/cloniks/merkletree"
	"github.com/ORBAT/cloniks/protocol"
)

// Config is the configuration for a directory tree. This includes the public part of the VRF key
// used to generate private indices, the cryptographic algorithms in use, as well as the protocol
// version number.
type Config struct {
	Version        []byte
	HashID         []byte
	VrfPublicKey   vrf.PublicKey
}

var _ merkletree.AssocData = (*Config)(nil)

var versionBs = []byte(protocol.Version)

var hashBs = []byte(hashed.HashID)

// NewConfig returns a new Config with the given public VRF key.
func NewConfig(vrfPublicKey vrf.PublicKey) *Config {
	return &Config{
		Version:        versionBs,
		HashID:         hashBs,
		VrfPublicKey:   vrfPublicKey,
	}
}

// Bytes serializes the config for signing the tree root. Default config serialization includes the
// library version, the cryptographic algorithms in use (i.e., the hashing algorithm) and the public
// part of the VRF key.
func (p *Config) Bytes() []byte {
	bs := make([]byte, 0, len(p.Version) + len(p.HashID) + len(p.VrfPublicKey) + 8)
	bs = append(bs, p.Version...)                                   // protocol version
	bs = append(bs, p.HashID...)                                    // cryptographic algorithms in use
	bs = append(bs, p.VrfPublicKey...)                              // vrf public key
	return bs
}

// GetConfig returns the Config included in the STR.
func GetConfig(str *merkletree.SignedTreeRoot) *Config {
	return str.Ad.(*Config)
}
