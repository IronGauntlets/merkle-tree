# merkle-tree

This package implements a simple Merkle Tree with the following features:

- Generate a merkle tree given some values
- Update the leaves
- Add new leaves
- Remove existing leaves
- Generate Merkle Proof
- Verify Merkle Proof

Currently, the implementation doesn't store intermediate nodes which means the tree has to be regenerated everytime 
a new proof needs to be created. In the future, this can be solved by either storing the node by their hash or path. 
This could be done in memory or stored on disk.