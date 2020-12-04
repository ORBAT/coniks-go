package merkletree

import (
	"bytes"

	"github.com/ORBAT/cloniks/conv"
	"github.com/ORBAT/cloniks/crypto/hashed"
	"github.com/ORBAT/cloniks/crypto/sign"
)

// AssocData is associated data to be hashed into the SignedTreeRoot.
type AssocData interface {
	Bytes() []byte
}

// SignedTreeRoot represents a signed tree root (STR), which is generated at the beginning of every
// epoch. Signed tree roots contain the current root node, the current and previous epochs, the hash
// of the previous STR, its signature, and developer-specified associated data. The epoch number is
// a counter from 0, and increases by 1 when a new signed tree root is issued by the PAD.
type SignedTreeRoot struct {
	tree            *MerkleTree
	TreeHash        []byte
	Epoch           uint64
	PreviousEpoch   uint64
	PreviousSTRHash []byte
	Signature       []byte
	Ad              AssocData `json:"-"`
}

// NewSTR constructs a SignedTreeRoot with the given signing key pair,
// associated data, MerkleTree, epoch, previous STR hash, and
// digitally signs the STR using the given signing key.
func NewSTR(key sign.PrivateKey, ad AssocData, m *MerkleTree, epoch uint64, prevHash []byte) *SignedTreeRoot {
	prevEpoch := epoch - 1
	if epoch == 0 {
		prevEpoch = 0
	}
	str := &SignedTreeRoot{
		tree:            m,
		TreeHash:        m.hash,
		Epoch:           epoch,
		PreviousEpoch:   prevEpoch,
		PreviousSTRHash: prevHash,
		Ad:              ad,
	}
	bytesPreSig := str.Bytes()
	str.Signature = key.Sign(bytesPreSig)
	return str
}

// Bytes serializes the signed tree root and its associated data into a specified format for
// signing. One should use this function for signing as well as verifying the signature. Any
// composition struct of SignedTreeRoot with a specific AssocData should override this method.
func (str *SignedTreeRoot) Bytes() []byte {
	return append(str.SerializeInternal(), str.Ad.Bytes()...)
}

// SerializeInternal serializes the signed tree root into a specified format.
func (str *SignedTreeRoot) SerializeInternal() []byte {
	var strBytes []byte
	strBytes = append(strBytes, conv.ULongToBytes(str.Epoch)...) // t - epoch number
	if str.Epoch > 0 {
		strBytes = append(strBytes, conv.ULongToBytes(str.PreviousEpoch)...) // t_prev - previous epoch number
	}
	strBytes = append(strBytes, str.TreeHash...)        // root
	strBytes = append(strBytes, str.PreviousSTRHash...) // previous STR hash
	return strBytes
}

// VerifyHashChain computes the hash of savedSTR's signature,
// and compares it to the hash of previous STR included
// in the issued STR. The hash chain is valid if
// these two hash values are equal and consecutive.
func (str *SignedTreeRoot) VerifyHashChain(savedSTR *SignedTreeRoot) bool {
	hash := hashed.Digest(savedSTR.Signature)
	return str.PreviousEpoch == savedSTR.Epoch &&
		str.Epoch == savedSTR.Epoch+1 &&
		bytes.Equal(hash, str.PreviousSTRHash)
}
