package merkle_tree

import (
	"crypto/sha256"
	"errors"
)

var HashFn = func(date []byte) [32]byte {
	return sha256.Sum256(date)
}

var ErrIndexOutOfRange = errors.New("index out of range")

type Node struct {
	Hash  [32]byte
	Left  *Node
	Right *Node
}

type MerkleTree struct {
	Root   *Node
	Leaves []*Node
}

type MerkleProof struct {
	i      int
	Hashes [][32]byte
}

func New(leaves [][]byte) *MerkleTree {
	if len(leaves) == 0 {
		return nil
	}

	var leafNodes []*Node
	for _, leaf := range leaves {
		leafNodes = append(leafNodes, &Node{Hash: HashFn(leaf)})
	}

	return buildTree(leafNodes)
}

func (m *MerkleTree) RootHash() [32]byte { return m.Root.Hash }

func (m *MerkleTree) AddLeaf(leaf []byte) {
	m.Leaves = append(m.Leaves, &Node{Hash: HashFn(leaf)})
	m.Root = buildTree(m.Leaves).Root
}

func (m *MerkleTree) UpdateLeaf(i int, leaf []byte) error {
	if i < 0 || i >= len(m.Leaves) {
		return ErrIndexOutOfRange
	}
	m.Leaves[i] = &Node{Hash: HashFn(leaf)}
	m.Root = buildTree(m.Leaves).Root
	return nil
}

func (m *MerkleTree) RemoveLeaf(i int) error {
	if i < 0 || i >= len(m.Leaves) {
		return ErrIndexOutOfRange
	}

	m.Leaves = append(m.Leaves[:i], m.Leaves[i+1:]...)
	m.Root = buildTree(m.Leaves).Root
	return nil
}

func (m *MerkleTree) GenerateProof(i int) (*MerkleProof, error) {
	if i < 0 || i >= len(m.Leaves) {
		return nil, ErrIndexOutOfRange
	}

	proof := &MerkleProof{i: i}
	nodes := m.Leaves

	for len(nodes) > 1 {
		var level []*Node
		var newI int

		for j := 0; j < len(nodes)-1; j += 2 {
			parentHash := HashFn(append(nodes[j].Hash[:], nodes[j+1].Hash[:]...))
			parent := &Node{Hash: parentHash, Left: nodes[j], Right: nodes[j+1]}
			level = append(level, parent)

			if i == j {
				proof.Hashes = append(proof.Hashes, nodes[j+1].Hash)
				newI = len(level) - 1
			}

			if i == j+1 {
				proof.Hashes = append(proof.Hashes, nodes[j].Hash)
				newI = len(level) - 1
			}

		}

		// If the nodes at any level are odd then append the node as is.
		if len(nodes)%2 == 1 {
			level = append(level, nodes[len(nodes)-1])
			if len(nodes)-1 == i {
				// There is no sibling
				newI = len(level) - 1
			}
		}

		nodes = level
		i = newI
	}

	return proof, nil
}

// buildTree generates a merkle tree from the leaves. If the leaves are odd, the last leave is not duplicated.
func buildTree(leaves []*Node) *MerkleTree {
	nodes := leaves
	for len(nodes) > 1 {
		var level []*Node
		for i := 0; i < len(nodes)-1; i += 2 {
			parentHash := HashFn(append(nodes[i].Hash[:], nodes[i+1].Hash[:]...))
			parent := &Node{Hash: parentHash, Left: nodes[i], Right: nodes[i+1]}
			level = append(level, parent)
		}

		// If the nodes at any level are odd then append the node as is.
		if len(nodes)%2 == 1 {
			level = append(level, nodes[len(nodes)-1])
		}

		nodes = level
	}

	return &MerkleTree{Root: nodes[0], Leaves: leaves}
}

func VerifyProof(leaf []byte, proof *MerkleProof, rootHash [32]byte) bool {
	hash, i := HashFn(leaf), proof.i

	// If the proof only has one hash and index is more than 0 than that means the index had no sibling until the root.
	// Since this index is even it will always be the right child of the root. Consider the following example
	// A B   C D  E
	// \ /   \ /  |
	//  AB   CD   E
	//    \  /    |
	//    ABCD    E
	//       \   /
	//       ABCDE
	if len(proof.Hashes) == 1 && i > 0 {
		return rootHash == HashFn(append(proof.Hashes[0][:], hash[:]...))
	}

	for _, siblingHash := range proof.Hashes {
		if i%2 == 0 {
			hash = HashFn(append(hash[:], siblingHash[:]...))
		} else {
			hash = HashFn(append(siblingHash[:], hash[:]...))
		}
		i /= 2
	}

	return rootHash == hash
}
