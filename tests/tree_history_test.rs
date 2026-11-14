use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

fn reference_root(mut hashes: Vec<[u8; 32]>) -> Option<[u8; 32]> {
    while hashes.len() > 1 {
        hashes = hashes
            .chunks(2)
            .map(|pair| Sha256::concat_and_hash(&pair[0], pair.get(1)))
            .collect();
    }
    hashes.first().copied()
}

#[test]
fn history_modes_produce_the_same_roots_and_proofs() {
    let leaves: Vec<_> = (0u32..300)
        .map(|i| Sha256::hash(&i.to_le_bytes()))
        .collect();
    for count in [
        0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 257,
    ] {
        let input = &leaves[..count];
        let mut history = MerkleTree::<Sha256>::from_leaves_iter(input.iter().copied());
        let mut no_history = MerkleTree::<Sha256, false>::from_leaves_iter(input.iter().copied());
        let original_root = reference_root(input.to_vec());
        assert_eq!(history.root(), original_root);
        assert_eq!(no_history.root(), original_root);
        assert_eq!(no_history.leaves_len(), count);

        let mut total = count;
        for batch in [1, 2, 7, 13] {
            let mut additions = leaves[total..total + batch].to_vec();
            history.append(&mut additions.clone());
            no_history.append(&mut additions);
            total += batch;
            let expected = reference_root(leaves[..total].to_vec());
            assert_eq!(history.uncommitted_root(), expected);
            assert_eq!(no_history.uncommitted_root(), expected);
            history.commit();
            no_history.commit();
            assert_eq!(history.root(), expected);
            assert_eq!(no_history.root(), expected);

            let mut indices = vec![0, total / 2, total - 1];
            indices.sort_unstable();
            indices.dedup();
            let proof = no_history.proof(&indices);
            assert_eq!(proof.to_bytes(), history.proof(&indices).to_bytes());
            let hashes: Vec<_> = indices.iter().map(|&i| leaves[i]).collect();
            assert!(proof.verify(expected.unwrap(), &indices, &hashes, total));
        }
        for _ in 0..4 {
            history.rollback();
        }
        assert_eq!(history.root(), original_root);
        history.rollback();
        assert_eq!(history.root(), None);

        let saved = no_history.clone();
        no_history.insert(Sha256::hash(b"uncommitted"));
        no_history.abort_uncommitted();
        assert_eq!(no_history.uncommitted_root(), None);
        assert_eq!(no_history.root(), saved.root());
    }
}
