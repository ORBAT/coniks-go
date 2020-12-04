package directory

import (
	"testing"

	"github.com/ORBAT/cloniks/crypto/sign"
	"github.com/ORBAT/cloniks/crypto/vrf"
	"github.com/ORBAT/cloniks/merkletree"
)

func TestVerifyHashChain(t *testing.T) {
	var N uint64 = 100

	vrfKey, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vrfPublicKey, _ := vrfKey.Public()
	pk := signKey.Public()

	policies := NewConfig(vrfPublicKey)
	pad, err := merkletree.NewPAD(policies, signKey, vrfKey, 1)
	if err != nil {
		panic(err)
	}

	savedSTR := pad.LatestSTR()

	for i := uint64(1); i < N; i++ {
		pad.Update(nil)
		str := pad.LatestSTR()
		if i != str.Epoch {
			t.Fatal("Epochs aren't increasing.")
		}
		if !pk.Verify(str.Bytes(), str.Signature) {
			t.Fatal("Invalid STR signature at epoch", i)
		}
		if !str.VerifyHashChain(savedSTR) {
			t.Fatal("Spurious STR at epoch", i)
		}
		savedSTR = str
	}
}
