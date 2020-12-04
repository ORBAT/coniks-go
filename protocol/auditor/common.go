package auditor

import (
	"fmt"

	"github.com/ORBAT/cloniks/crypto/hashed"
	"github.com/ORBAT/cloniks/directory"
)

// ComputeDirectoryIdentity returns the hash of
// the directory's initial STR as a byte array.
// It panics if the STR isn't an initial STR (i.e. str.Epoch != 0).
func ComputeDirectoryIdentity(str *directory.SignedTreeRoot) [hashed.HashSizeByte]byte {
	if str.Epoch != 0 {
		panic(fmt.Sprintf("[coniks] Expect epoch 0, got %x", str.Epoch))
	}

	var initSTRHash [hashed.HashSizeByte]byte
	copy(initSTRHash[:], hashed.Digest(str.Signature))
	return initSTRHash
}
