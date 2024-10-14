package merkle_tree_test

import (
	"fmt"
	"testing"

	merkleTree "github.com/IronGauntlets/merkle-tree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMerkleTree(t *testing.T) {
	leaves := [][]byte{[]byte("l1"), []byte("l2"), []byte("l3"), []byte("l4")}

	t.Run("merkle tree is nil if no leaves are provided", func(t *testing.T) {
		tree := merkleTree.New([][]byte{})
		assert.Nil(t, tree)
	})

	t.Run("merkle tree is nil if nil leaves are provided", func(t *testing.T) {
		tree := merkleTree.New(nil)
		assert.Nil(t, tree)
	})

	t.Run("merkle tree with all even level", func(t *testing.T) {
		tree := merkleTree.New(leaves)
		assert.Equal(t, CalculateMerkleRoot(leaves), tree.RootHash())
	})

	t.Run("merkle tree with odd leaves", func(t *testing.T) {
		leaves = append(leaves, []byte("l5"))
		tree := merkleTree.New(leaves)
		assert.Equal(t, CalculateMerkleRoot(leaves), tree.RootHash())
	})

	t.Run("merkle tree with some even and some odd level", func(t *testing.T) {
		leaves = append(leaves, []byte("l6"))
		tree := merkleTree.New(leaves)
		assert.Equal(t, CalculateMerkleRoot(leaves), tree.RootHash())
	})

}

func TestAddLeaf(t *testing.T) {
	leaves := [][]byte{[]byte("l1"), []byte("l2"), []byte("l3"), []byte("l4"), []byte("l5")}
	tree := merkleTree.New(leaves)
	newLeaf := []byte("newLeaf")
	tree.AddLeaf(newLeaf)

	assert.Equal(t, CalculateMerkleRoot(append(leaves, newLeaf)), tree.RootHash())
}

func TestUpdateLeaf(t *testing.T) {
	leaves := [][]byte{[]byte("l1"), []byte("l2"), []byte("l3"), []byte("l4")}

	t.Run("error if index is out of range", func(t *testing.T) {
		tree := merkleTree.New(leaves)
		assert.Error(t, merkleTree.ErrIndexOutOfRange, tree.UpdateLeaf(-1, []byte("updatedLeaf")))
		assert.Error(t, merkleTree.ErrIndexOutOfRange, tree.UpdateLeaf(len(leaves), []byte("updatedLeaf")))
	})

	t.Run("update leaf at index 3", func(t *testing.T) {
		tree := merkleTree.New(leaves)
		updatedLeaf := []byte("updatedLeaf")
		require.NoError(t, tree.UpdateLeaf(3, updatedLeaf))

		assert.Equal(t, CalculateMerkleRoot(append(leaves[:3], updatedLeaf)), tree.RootHash())
	})
}

func TestRemoveLeaf(t *testing.T) {
	leaves := [][]byte{[]byte("l1"), []byte("l2"), []byte("l3"), []byte("l4")}

	t.Run("error if index is out of range", func(t *testing.T) {
		tree := merkleTree.New(leaves)
		assert.Error(t, merkleTree.ErrIndexOutOfRange, tree.RemoveLeaf(-1))
		assert.Error(t, merkleTree.ErrIndexOutOfRange, tree.RemoveLeaf(len(leaves)))
	})

	t.Run("remove leaf at index 3", func(t *testing.T) {
		tree := merkleTree.New(leaves)
		i := 3
		require.NoError(t, tree.RemoveLeaf(i))
		assert.Equal(t, CalculateMerkleRoot(leaves[:i]), tree.RootHash())
	})

	t.Run("remove leaf at index 2", func(t *testing.T) {
		tree := merkleTree.New(leaves)
		i := 2
		require.NoError(t, tree.RemoveLeaf(i))
		assert.Equal(t, CalculateMerkleRoot(append(leaves[:i], leaves[i+1:]...)), tree.RootHash())
	})
}

func CalculateMerkleRoot(leaves [][]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}

	var hashedLeaves [][32]byte
	for _, h := range leaves {
		hashedLeaves = append(hashedLeaves, merkleTree.HashFn(h[:]))
	}
	return calculateMerkleRoot(hashedLeaves)
}

func calculateMerkleRoot(hashes [][32]byte) [32]byte {
	if len(hashes) == 1 {
		return hashes[0]
	}

	var intermediateHashes [][32]byte

	for i := 0; i < len(hashes)-1; i = i + 2 {
		intermediateHashes = append(intermediateHashes, merkleTree.HashFn(append(hashes[i][:], hashes[i+1][:]...)))
	}

	if len(hashes)%2 == 1 {
		intermediateHashes = append(intermediateHashes, hashes[len(hashes)-1])
	}
	return calculateMerkleRoot(intermediateHashes)
}

func TestGenerateAndVerifyProof(t *testing.T) {
	leaves := [][]byte{[]byte("l1"), []byte("l2"), []byte("l3"), []byte("l4"), []byte("l5")}

	testCases := []struct {
		name   string
		leaves [][]byte
	}{
		{"single Leaf", leaves[:1]},
		{"two leaves", leaves[:2]},
		{"three leaves", leaves[:3]},
		{"four leaves", leaves[:4]},
		{"five leaves", leaves[:5]},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tree := merkleTree.New(tc.leaves)

			for i, leaf := range tc.leaves {
				t.Run(fmt.Sprintf("leaf at index %d", i), func(t *testing.T) {
					proof, err := tree.GenerateProof(i)
					require.NoError(t, err)
					assert.True(t, merkleTree.VerifyProof(leaf, proof, tree.RootHash()))
				})
			}
		})
	}

	t.Run("error if invalid index", func(t *testing.T) {
		tree := merkleTree.New(leaves)

		_, err := tree.GenerateProof(-1)
		assert.Error(t, merkleTree.ErrIndexOutOfRange, err)

		_, err = tree.GenerateProof(len(leaves))
		assert.Error(t, merkleTree.ErrIndexOutOfRange, err)

	})

	t.Run("incorrect proof", func(t *testing.T) {
		t.Run("wrong root hash", func(t *testing.T) {
			t1 := merkleTree.New(leaves)
			t2 := merkleTree.New(leaves[:len(leaves)-1])

			p1, err := t1.GenerateProof(1)
			require.NoError(t, err)

			assert.False(t, merkleTree.VerifyProof(leaves[1], p1, t2.RootHash()))
		})

		t.Run("modified proof", func(t *testing.T) {
			tree := merkleTree.New(leaves)

			p, err := tree.GenerateProof(1)
			require.NoError(t, err)

			p.Hashes[0][0] = 0x08

			assert.False(t, merkleTree.VerifyProof(leaves[1], p, tree.RootHash()))
		})
	})

}
