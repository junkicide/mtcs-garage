#![no_main]

use bincode::serialize;
use ed25519_consensus::*;
use mtcs_core::*;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof};
sp1_zkvm::entrypoint!(main);

pub fn main() {
    println!("reading inputs into guest...");

    let cycle: Cycle = sp1_zkvm::io::read::<Cycle>();
    let key: SigningKey = sp1_zkvm::io::read::<SigningKey>();
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
            leaves.push(Sha256::hash(&serialize(&x).unwrap()));
            &x.to
        } else {
            panic!("cycle invalid")
        }
    });

    assert_eq!(&from, to);
    let indexes = merkle_data.indexes;
    let proof: MerkleProof<Sha256> = MerkleProof::<Sha256>::try_from(proof.bytes).unwrap();
    assert!(proof.verify(
        merkle_data.merkle_root,
        &indexes,
        leaves.get(..).ok_or("couldn't fetch leaves").unwrap(),
        merkle_data.len
    ));
    println!("creating commitments for public data...");

    let message = {
        let hashed_cycle = Sha256::hash(&serialize(&cycle).unwrap());
        // Generate a signing key and sign the message

        let sig = key.sign(&bincode::serialize(&hashed_cycle).unwrap()[..]);

        let vk_bytes: [u8; 32] = VerificationKey::from(&key).into();

        (hashed_cycle, vk_bytes, sig)
    };

    sp1_zkvm::io::commit(&message);
    println!("cryptography magic happening...")
}
// TODO: for every edge involved in clearing, the total offsets of all cycles
// passing through that edge should be less than the value of that edge

// TODO:need to make sure that the same cycle doesn't appear
// twice in the same clearing epoch
