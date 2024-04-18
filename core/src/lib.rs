use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateKey {
    pub key: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Proof {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MerkleData {
    pub merkle_root: [u8; 32],
    pub indexes: Vec<usize>,
    pub len: usize,
}

pub type Address = [u8; 20];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Obligation {
    pub from: Address,
    pub to: Address,
    pub value: u8, // TODO: make this u32 or higher
    pub salt: [u8; 32],
}

pub type ObligationList = Vec<Obligation>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Cycle {
    pub setoff: u8,
    pub size: usize,
    pub obligations: ObligationList,
}
