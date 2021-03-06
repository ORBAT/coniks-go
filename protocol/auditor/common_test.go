package auditor

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ORBAT/cloniks/directory"
)

func TestComputeDirectoryIdentity(t *testing.T) {
	// TODO:
	t.Skip("figure out test vector for this")
	d := directory.NewTestTree(t)
	str0 := d.LatestSTR()
	d.Update()
	str1 := d.LatestSTR()

	for _, tc := range []struct {
		name string
		str  *directory.SignedTreeRoot
		want []byte
	}{
		{"normal", str0, hex2bin("fd0584f79054f8113f21e5450e0ad21c9221fc159334c7bc1644e3e2a0fb5060")},
		{"panic", str1, []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "panic" {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("The code did not panic")
					}
				}()
			}
			if got, want := ComputeDirectoryIdentity(tc.str), tc.want; !bytes.Equal(got[:], want) {
				t.Errorf("ComputeDirectoryIdentity() = %x, want %x", got, want)
			}
		})
	}
}

// decode hex string to byte array
func hex2bin(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return result
}
