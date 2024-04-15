#![no_main]

use bincode::serialize;
use mtcs_core::*;
use rs_merkle::{algorithms::Sha256 as MerkleSha256, Hasher, MerkleProof};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    println!("reading inputs into guest...");

    let cycle: Cycle = sp1_zkvm::io::read::<Cycle>();
    let _secret: PrivateKey = sp1_zkvm::io::read::<PrivateKey>();
    let proof: Proof = sp1_zkvm::io::read::<Proof>();
    let merkle_data: MerkleData = sp1_zkvm::io::read::<MerkleData>();
    assert_eq!(
        cycle.size,
        cycle.obligations.len(),
        "cycle size does not match number of obligations"
    );
    assert!(
        cycle.size > 2,
        "invalid cycle, length is {}, should be atleast 3",
        cycle.size
    );

    let mut leaves: Vec<[u8; 32]> = vec![];
    println!("running validity checks...");

    let from = &cycle.obligations.first().unwrap().from;

    let to = &cycle.obligations.iter().fold(from, |acc, x| {
        if &x.from == acc && &x.value >= &cycle.setoff {
            leaves.push(MerkleSha256::hash(&serialize(&x).unwrap()));
            &x.to
        } else {
            panic!("cycle invalid")
        }
    });

    assert_eq!(&from, to);
    let indexes = merkle_data.indexes;
    let proof: MerkleProof<MerkleSha256> =
        MerkleProof::<MerkleSha256>::try_from(proof.bytes).unwrap();
    assert!(proof.verify(
        merkle_data.merkle_root,
        &indexes,
        leaves.get(..).ok_or("couldn't fetch leaves").unwrap(),
        merkle_data.len
    ));
    println!("creating commitments for public data");
    sp1_zkvm::io::commit(&cycle);
}
// TODO: for every edge involved in clearing, the total offsets of all cycles
// passing through that edge should be less than the value of that edge

// TODO:need to make sure that the same cycle doesn't appear
// twice in the same clearing epoch
