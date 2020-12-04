package hashed

import (
	"bytes"
	"testing"

	// "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDigest(t *testing.T) {
	msg := []byte("test message")
	d := Digest(msg)
	if len(d) != HashSizeByte {
		t.Fatal("Computation of Hash failed.")
	}

	if bytes.Equal(d, make([]byte, HashSizeByte)) {
		t.Fatal("Hash is all zeros.")
	}
	require.Equal(t, Digest(msg), d)
}

func TestMakeRand(t *testing.T) {
	r := RandSlice()
	// check if hashed the random output:
	if len(r) != HashSizeByte {
		t.Fatal("Looks like Digest wasn't called correctly.")
	}
}

func TestCommit(t *testing.T) {
	stuff := [][]byte{{1, 2, 3}, {4, 5, 6}}
	commit := NewCommit(stuff...)

	if !commit.Verify(stuff...) {
		t.Fatal("Commit doesn't verify!")
	}
}
