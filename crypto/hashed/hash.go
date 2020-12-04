package hashed

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/zeebo/blake3"
	"lukechampine.com/frand"
)

const (
	// HashSizeByte is the size of the hash output in bytes.
	HashSizeByte = 32
	// HashID identifies the used hash as a string.
	HashID = "BLAKE3"
)

type Hasher = blake3.Hasher

func New() *blake3.Hasher {
	return blake3.New()
}

func NewKeyed(context string, material []byte) *blake3.Hasher {
	key := make([]byte, 32)
	blake3.DeriveKey(context, material, key)
	h, err := blake3.NewKeyed(key)
	if err != nil {
		panic(fmt.Errorf("create keyed BLAKE3 hash: %w", err))
	}
	return h
}

// Digest hashes all passed byte slices.
// The passed slices won't be mutated.
func Digest(ms ...[]byte) (ret []byte) {
	h := hasherPool.Get().(*Hasher)
	for _, m := range ms {
		_, _ = h.Write(m)
	}

	ret = make([]byte, 0, h.Size())

	sum := h.Sum(ret)
	h.Reset()
	hasherPool.Put(h)
	return sum
}

// RandSlice returns a random slice of bytes from a fast user-space CSPRNG
func RandSlice() []byte {
	return frand.Bytes(32)
}

// Commit can be used to create a cryptographic commit to some value. See NewCommit
type Commit struct {
	// Salt is a cryptographic salt which will be hashed in addition
	// to the value.
	Salt []byte
	// Hash is the hash of the committed value and the salt
	Hash []byte
}

// CommitHashCtx is the blake3 context for commits.
// It can't be changed between versions, otherwise commits will not verify between versions
const CommitHashCtx = "clonics commit v1"

// NewCommit creates a new cryptographic commitment to the given values (which won't be mutated)
func NewCommit(values ...[]byte) Commit {
	salt := RandSlice()
	commitHash := CommitHash(values, salt)
	return Commit{
		Salt: salt,
		Hash: commitHash,
	}
}

func CommitHash(values [][]byte, salt []byte) []byte {
	h := NewKeyed(CommitHashCtx, salt)
	for _, bs := range values {
		_, _ = h.Write(bs)
	}
	commitHash := h.Sum(make([]byte, 0, HashSizeByte))
	return commitHash
}

// Verify verifies that the underlying commit c was a commitment to the given values
func (c Commit) Verify(values ...[]byte) bool {
	return bytes.Equal(c.Hash, CommitHash(values, c.Salt))
}

func newHasher() interface{} {
	return New()
}

var hasherPool = sync.Pool{
	New: newHasher,
}