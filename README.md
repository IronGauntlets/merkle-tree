# merkle-tree

This package implements a simple Merkle Tree with the following features:

- Generate a merkle tree given some values
- Update the leaves
- Add new leaves
- Remove existing leaves
- Generate Merkle Proof
- Verify Merkle Proof

Currently, the implementation doesn't store intermediate nodes, meaning the tree has to be regenerated every time a new proof is created. This can be solved in the future by storing the nodes by their hash or path.
