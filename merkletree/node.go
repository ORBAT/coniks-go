package merkletree

import (
	"github.com/ORBAT/cloniks/conv"
	"github.com/ORBAT/cloniks/crypto/hashed"
)

type node struct {
	parent merkleNode
	level  uint32
}

type interiorNode struct {
	node
	leftChild  merkleNode
	rightChild merkleNode
	leftHash   []byte
	rightHash  []byte
}

type userLeafNode struct {
	node
	key        string
	value      []byte
	index      []byte
	// TODO:
	//  - epoch when this was added / changed
	//  - in the future allowsUnsignedChanges & allowsPublicVisibility would be neat
	commitment hashed.Commit
}

type emptyNode struct {
	node
	index []byte
}

func newInteriorNode(parent merkleNode, level uint32, prefixBits []bool) *interiorNode {
	prefixLeft := copyOfBools(prefixBits, false)
	prefixRight := copyOfBools(prefixBits, true)
	leftBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
		index: conv.ToBytes(prefixLeft),
	}

	rightBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
		index: conv.ToBytes(prefixRight),
	}
	newNode := &interiorNode{
		node: node{
			parent: parent,
			level:  level,
		},
		leftChild:  leftBranch,
		rightChild: rightBranch,
	}
	leftBranch.parent = newNode
	rightBranch.parent = newNode

	return newNode
}

type nodeKind uint8

const (
	_ nodeKind = iota
	userLeafNodeKind
	interiorNodeKind
	emptyNodeKind
)

type merkleNode interface {
	kind() nodeKind
	hash(*MerkleTree) []byte
	clone(*interiorNode) merkleNode
}

var _ merkleNode = (*userLeafNode)(nil)
var _ merkleNode = (*interiorNode)(nil)
var _ merkleNode = (*emptyNode)(nil)

func (n *interiorNode) hash(m *MerkleTree) []byte {
	if n.leftHash == nil {
		n.leftHash = n.leftChild.hash(m)
	}
	if n.rightHash == nil {
		n.rightHash = n.rightChild.hash(m)
	}
	return hashed.Digest(n.leftHash, n.rightHash)
}

var emptyLeafBs = []byte{LeafIdentifier}
func (n *userLeafNode) hash(m *MerkleTree) []byte {
	return hashed.Digest(
		emptyLeafBs,                               // K_leaf
		[]byte(m.nonce),                     // K_n
		[]byte(n.index),                     // i
		[]byte(conv.UInt32ToBytes(n.level)), // l
		[]byte(n.commitment.Value),          // commit(key|| value)
	)
}

var emptyBranchBs = []byte{EmptyBranchIdentifier}
func (n *emptyNode) hash(m *MerkleTree) []byte {
	return hashed.Digest(
		emptyBranchBs,                               // K_empty
		[]byte(m.nonce),                     // K_n
		[]byte(n.index),                     // i
		[]byte(conv.UInt32ToBytes(n.level)), // l
	)
}

func (n *interiorNode) clone(parent *interiorNode) merkleNode {
	newNode := &interiorNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		leftHash:  copyOfBs(n.leftHash),
		rightHash: copyOfBs(n.rightHash),
	}
	if n.leftChild == nil ||
		n.rightChild == nil {
		panic(ErrInvalidTree)
	}
	newNode.leftChild = n.leftChild.clone(newNode)
	newNode.rightChild = n.rightChild.clone(newNode)
	return newNode
}

func (n *userLeafNode) clone(parent *interiorNode) merkleNode {
	return &userLeafNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		key:        n.key,
		value:      copyOfBs(n.value),
		index:      copyOfBs(n.index),
		commitment: n.commitment,
	}
}

func (n *emptyNode) clone(parent *interiorNode) merkleNode {
	return &emptyNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		index: copyOfBs(n.index),
	}
}

func (*userLeafNode) kind() nodeKind {
	return userLeafNodeKind
}

func (*interiorNode) kind() nodeKind {
	return interiorNodeKind
}

func (*emptyNode) kind() nodeKind {
	return emptyNodeKind
}

func isEmpty(n merkleNode) bool {
	return n.kind() == emptyNodeKind
}

func copyOfBs(bs []byte) (c []byte) {
	c = make([]byte, len(bs))
	copy(c, bs)
	return
}

func copyOfBools(bs []bool, extra ...bool) (c []bool) {
	c = make([]bool, len(bs) + len(extra))
	copy(c, bs)
	if len(extra) != 0 {
		copy(c[len(bs):], extra)
	}
	return
}