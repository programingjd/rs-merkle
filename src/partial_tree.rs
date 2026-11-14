use crate::prelude::*;
use crate::{error::Error, utils, Hasher};

type PartialTreeLayer<H> = Vec<(usize, H)>;

/// Partial tree represents a part of the original tree that is enough to calculate the root.
/// Used in to extract the root in a merkle proof, to apply diff to a tree or to merge
/// multiple trees into one.
///
/// It is a rare case when you need to use this struct on it's own. It's mostly used inside
/// [`MerkleTree`] and [`MerkleProof`]
///
/// [`MerkleTree`]: crate::MerkleTree
/// [`MerkleProof`]: crate::MerkleProof
#[derive(Clone)]
pub struct PartialTree<T: Hasher> {
    pub(crate) layers: Vec<Vec<(usize, T::Hash)>>,
}

impl<T: Hasher> Default for PartialTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Hasher> PartialTree<T> {
    /// Takes leaves (item hashes) as an argument and build a Merkle Tree from them.
    /// Since it's a partial tree, hashes must be accompanied by their index in the original tree.
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// This is a helper function to build a full tree from a full set of leaves without any
    /// helper indices
    pub fn from_leaves(leaves: &[T::Hash]) -> Result<Self, Error> {
        Self::from_leaves_iter(leaves.iter().copied())
    }

    pub(crate) fn from_leaves_iter(
        leaves: impl IntoIterator<Item = T::Hash>,
    ) -> Result<Self, Error> {
        let leaves = leaves.into_iter();
        // Leave room for one appended leaf without reallocating the base layer.
        let mut leaf_tuples = Vec::with_capacity(leaves.size_hint().0.saturating_add(1));
        leaf_tuples.extend(leaves.enumerate());
        let depth = utils::indices::tree_depth(leaf_tuples.len());
        Self::build(vec![leaf_tuples], depth)
    }

    pub fn build(partial_layers: Vec<Vec<(usize, T::Hash)>>, depth: usize) -> Result<Self, Error> {
        let layers = Self::build_tree(partial_layers, depth)?;
        Ok(Self { layers })
    }

    /// This is a general algorithm for building a partial tree. It can be used to extract root
    /// from merkle proof, or if a complete set of leaves provided as a first argument and no
    /// helper indices given, will construct the whole tree.
    fn build_tree(
        partial_layers: Vec<Vec<(usize, T::Hash)>>,
        full_tree_depth: usize,
    ) -> Result<Vec<PartialTreeLayer<T::Hash>>, Error> {
        let mut partial_tree: Vec<Vec<(usize, T::Hash)>> = Vec::new();
        let mut current_layer = Vec::new();

        let mut helper_layers = partial_layers.into_iter();

        // This iterates to full_tree_depth and not to the partial_layers_len because
        // when constructing

        // It is iterating to full_tree_depth instead of partial_layers.len to address the case
        // of applying changes to a tree when tree requires a resize, and partial layer len
        // in that case going to be lower that the resulting tree depth
        for _ in 0..full_tree_depth {
            // Appending helper nodes to the current known nodes
            if let Some(mut nodes) = helper_layers.next() {
                if current_layer.is_empty() {
                    current_layer = nodes;
                } else {
                    current_layer.append(&mut nodes);
                }
            }
            current_layer.sort_unstable_by_key(|(index, _)| *index);

            let mut parents = Vec::with_capacity(utils::indices::div_ceil(current_layer.len(), 2));
            let mut previous_parent = None;
            for &(index, _) in &current_layer {
                let parent_index = index / 2;
                if previous_parent == Some(parent_index) {
                    continue;
                }
                let child_index = parents.len() * 2;
                let left = &current_layer
                    .get(child_index)
                    .ok_or_else(Error::not_enough_helper_nodes)?
                    .1;
                let right = current_layer.get(child_index + 1).map(|(_, hash)| hash);
                parents.push((parent_index, T::concat_and_hash(left, right)));
                previous_parent = Some(parent_index);
            }

            partial_tree.push(current_layer);
            current_layer = parents;
        }

        partial_tree.push(current_layer);

        Ok(partial_tree)
    }

    /// Returns how many layers there is between leaves and the root
    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    /// Return the root of the tree
    pub fn root(&self) -> Option<&T::Hash> {
        Some(&self.layers.last()?.first()?.1)
    }

    pub fn contains(&self, layer_index: usize, node_index: usize) -> bool {
        match self.layers().get(layer_index) {
            Some(layer) => layer.iter().any(|(index, _)| *index == node_index),
            None => false,
        }
    }

    /// Consumes other partial tree into itself, replacing any conflicting nodes with nodes from
    /// `other` in the process. Doesn't rehash the nodes, so the integrity of the result is
    /// not verified. It gives an advantage in speed, but should be used only if the integrity of
    /// the tree can't be broken, for example, it is used in the `.commit` method of the
    /// `MerkleTree`, since both partial trees are essentially constructed in place and there's
    /// no need to verify integrity of the result.
    pub fn merge_unverified(&mut self, other: Self) {
        for (layer_index, nodes) in other.layers.into_iter().enumerate() {
            if let Some(layer) = self.layers.get_mut(layer_index) {
                if layer.is_empty() {
                    *layer = nodes;
                    continue;
                }
                let additional = nodes
                    .iter()
                    .filter(|(index, _)| layer.binary_search_by_key(index, |(i, _)| *i).is_err())
                    .count();
                // Reserve only for new nodes, not for replacements or a doubled layer.
                layer.reserve_exact(additional);
                for (index, hash) in nodes {
                    match layer.binary_search_by_key(&index, |(i, _)| *i) {
                        Ok(position) => layer[position].1 = hash,
                        Err(position) => layer.insert(position, (index, hash)),
                    }
                }
            } else {
                self.layers.push(nodes);
            }
        }
    }

    pub fn layer_nodes(&self) -> Vec<Vec<T::Hash>> {
        let hashes: Vec<Vec<T::Hash>> = self
            .layers()
            .iter()
            .map(|layer| layer.iter().cloned().map(|(_, hash)| hash).collect())
            .collect();

        hashes
    }

    /// Returns partial tree layers
    pub fn layers(&self) -> &[Vec<(usize, T::Hash)>] {
        &self.layers
    }

    /// Clears all elements in the ree
    pub fn clear(&mut self) {
        self.layers.clear();
    }
}

#[cfg(all(test, feature = "sha2"))]
mod tests {
    use super::*;
    use crate::algorithms::Sha256;

    #[test]
    fn merge_replaces_and_inserts_nodes_without_discarding_deeper_layers() {
        let mut tree = PartialTree::<Sha256> {
            layers: vec![
                vec![(0, [0; 32]), (2, [2; 32]), (4, [4; 32])],
                vec![(0, [9; 32])],
            ],
        };
        let other = PartialTree::<Sha256> {
            layers: vec![vec![(1, [1; 32]), (2, [8; 32]), (5, [5; 32])]],
        };
        tree.merge_unverified(other);
        assert_eq!(
            tree.layers[0],
            vec![
                (0, [0; 32]),
                (1, [1; 32]),
                (2, [8; 32]),
                (4, [4; 32]),
                (5, [5; 32])
            ]
        );
        assert_eq!(tree.layers[1], vec![(0, [9; 32])]);
        tree.merge_unverified(PartialTree::new());
        assert_eq!(tree.layers[0].len(), 5);
        let mut empty = PartialTree::<Sha256>::new();
        empty.merge_unverified(tree.clone());
        assert_eq!(empty.layers, tree.layers);
    }
}
