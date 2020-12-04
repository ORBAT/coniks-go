package merkletree

import (
	"bytes"
	"errors"

	"github.com/ORBAT/cloniks/conv"
	"github.com/ORBAT/cloniks/crypto/hashed"
)

var (
	// ErrInvalidTree indicates a panic due to
	// a malformed operation on the tree.
	ErrInvalidTree = errors.New("[merkletree] Invalid tree")
)

const (
	// EmptyBranchIdentifier is the domain separation prefix for
	// empty node hashes.
	EmptyBranchIdentifier = 'E'

	// LeafIdentifier is the domain separation prefix for user
	// leaf node hashes.
	LeafIdentifier = 'L'
)

// MerkleTree represents the Merkle prefix tree data structure,
// which includes the root node, its hash, and a random tree-specific
// nonce.
type MerkleTree struct {
	nonce []byte
	root  *interiorNode
	hash  []byte
}

// NewMerkleTree returns an empty Merkle prefix tree
// with a secure random nonce. The tree root is an interior node
// and its children are two empty leaf nodes.
func NewMerkleTree() (*MerkleTree, error) {
	root := newInteriorNode(nil, 0, []bool{})
	nonce := hashed.RandSlice()
	m := &MerkleTree{
		nonce: nonce,
		root:  root,
	}
	return m, nil
}

// Get returns an AuthenticationPath used as a proof of inclusion/absence for the requested
// lookupIndex.
func (m *MerkleTree) Get(lookupIndex []byte) *AuthenticationPath {
	lookupIndexBits := conv.ToBits(lookupIndex)
	depth := 0
	var nodePointer merkleNode
	nodePointer = m.root

	authPath := &AuthenticationPath{
		TreeNonce:   m.nonce,
		LookupIndex: lookupIndex,
	}

	searchLoop: for {
		switch nodePointer.kind() {
		case userLeafNodeKind, emptyNodeKind:
			// reached a leaf node or an empty branch
			break searchLoop
		}

		direction := lookupIndexBits[depth]
		var hashArr [hashed.HashSizeByte]byte
		if direction {
			copy(hashArr[:], nodePointer.(*interiorNode).leftHash)
			nodePointer = nodePointer.(*interiorNode).rightChild
		} else {
			copy(hashArr[:], nodePointer.(*interiorNode).rightHash)
			nodePointer = nodePointer.(*interiorNode).leftChild
		}
		authPath.PrunedTree = append(authPath.PrunedTree, hashArr)
		depth++
	}

	if nodePointer == nil {
		panic(ErrInvalidTree)
	}

	switch nodePointer.kind() {
	case userLeafNodeKind:
		pNode := nodePointer.(*userLeafNode)
		authPath.Leaf = &ProofNode{
			Level:   pNode.level,
			Index:   pNode.index,
			Value:   pNode.value,
			IsEmpty: false,
			Commitment: pNode.commitment,
		}
		if bytes.Equal(pNode.index, lookupIndex) {
			return authPath
		}
		// reached a different leaf with a matching prefix
		// return a auth path including the leaf node without salt & value
		authPath.Leaf.Value = nil
		authPath.Leaf.Commitment.Salt = nil
		return authPath
	case emptyNodeKind:
		pNode := nodePointer.(*emptyNode)
		authPath.Leaf = &ProofNode{
			Level:      pNode.level,
			Index:      pNode.index,
			Value:      nil,
			IsEmpty:    true,
		}
		return authPath
	}
	panic(ErrInvalidTree)
}

// Set inserts or updates the key and value of the given index. It will generate a new commitment
// for the leaf node. In the case of an update, the leaf node's value and
// commitment are replaced with the new value and newly generated
// commitment.
func (m *MerkleTree) Set(index []byte, key string, value []byte) error {
	// TODO: see todo note in userLeafNode
	commitment := hashed.NewCommit([]byte(key), value)
	toAdd := userLeafNode{
		key:        key,
		value:      copyOfBs(value),
		index:      index,
		commitment: commitment,
	}
	m.insertNode(index, &toAdd)
	return nil
}

func (m *MerkleTree) insertNode(index []byte, toAdd *userLeafNode) {
	indexBits := conv.ToBits(index)
	var depth uint32 // = 0
	var nodePointer merkleNode
	nodePointer = m.root

insertLoop:
	for {
		switch nodePointer.kind() {
		case userLeafNodeKind:
			// reached a "bottom" of the tree.
			// add a new interior node and push the previous leaf down
			// then continue insertion
			currentNodeUL := nodePointer.(*userLeafNode)
			if currentNodeUL.parent == nil {
				panic(ErrInvalidTree)
			}

			if bytes.Equal(currentNodeUL.index, toAdd.index) {
				// replace the value
				toAdd.parent = currentNodeUL.parent
				toAdd.level = currentNodeUL.level
				*currentNodeUL = *toAdd
				return
			}

			newInteriorNode := newInteriorNode(currentNodeUL.parent, depth, indexBits[:depth])

			direction := conv.GetNthBit(currentNodeUL.index, depth)
			if direction {
				newInteriorNode.rightChild = currentNodeUL
			} else {
				newInteriorNode.leftChild = currentNodeUL
			}
			currentNodeUL.level = depth + 1
			currentNodeUL.parent = newInteriorNode

			if parent := newInteriorNode.parent.(*interiorNode); parent.leftChild == nodePointer {
				parent.leftChild = newInteriorNode
			} else {
				parent.rightChild = newInteriorNode
			}
			nodePointer = newInteriorNode
		case interiorNodeKind:
			currentNodeI := nodePointer.(*interiorNode)
			direction := indexBits[depth]
			if direction { // go right
				currentNodeI.rightHash = nil
				if isEmpty(currentNodeI.rightChild) {
					currentNodeI.rightChild = toAdd
					toAdd.level = depth + 1
					toAdd.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.rightChild
				}
			} else { // go left
				currentNodeI.leftHash = nil
				if isEmpty(currentNodeI.leftChild) {
					currentNodeI.leftChild = toAdd
					toAdd.level = depth + 1
					toAdd.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.leftChild
				}
			}
			depth += 1
		default:
			panic(ErrInvalidTree)
		}
	}
}

// visits all leaf-nodes and calls callBack on each of them
// doesn't modify the underlying tree m
func (m *MerkleTree) visitLeafNodes(callBack func(*userLeafNode)) {
	visitULNsInternal(m.root, callBack)
}

func visitULNsInternal(nodePtr merkleNode, callBack func(*userLeafNode)) {
	switch nodePtr.kind() {
	case userLeafNodeKind:
		callBack(nodePtr.(*userLeafNode))
	case interiorNodeKind:
		if leftChild := nodePtr.(*interiorNode).leftChild; leftChild != nil {
			visitULNsInternal(leftChild, callBack)
		}
		if rightChild := nodePtr.(*interiorNode).rightChild; rightChild != nil {
			visitULNsInternal(rightChild, callBack)
		}
	case emptyNodeKind:
		// do nothing
	default:
		panic(ErrInvalidTree)
	}
}

func (m *MerkleTree) recomputeHash() {
	m.hash = m.root.hash(m)
}

// Clone returns a copy of the tree m.
// Any later change to the original tree m does not affect the cloned tree,
// and vice versa.
func (m *MerkleTree) Clone() *MerkleTree {
	return &MerkleTree{
		nonce: copyOfBs(m.nonce),
		root:  m.root.clone(nil).(*interiorNode),
		hash:  copyOfBs(m.hash),
	}
}
