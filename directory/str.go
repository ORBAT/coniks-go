package directory

import "github.com/ORBAT/cloniks/merkletree"

// SignedTreeRoot
type SignedTreeRoot struct {
	*merkletree.SignedTreeRoot
	Policies *Config
}

// NewDirSTR constructs a new SignedTreeRoot from a merkletree.SignedTreeRoot
func NewDirSTR(str *merkletree.SignedTreeRoot) *SignedTreeRoot {
	return &SignedTreeRoot{
		str,
		str.Ad.(*Config),
	}
}

// Serialize overrides merkletree.SignedTreeRoot.Bytes
func (str *SignedTreeRoot) Bytes() []byte {
	return append(str.SerializeInternal(), str.Policies.Bytes()...)
}

// VerifyHashChain shadows merkletree.SignedTreeRoot.VerifyHashChain
func (str *SignedTreeRoot) VerifyHashChain(savedSTR *SignedTreeRoot) bool {
	return str.SignedTreeRoot.VerifyHashChain(savedSTR.SignedTreeRoot)
}
