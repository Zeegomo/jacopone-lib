use crate::utils::{sha2_256, sha3_256};

pub trait RoundFunction {
    fn apply(input: &[u8], key: &[u8]) -> Vec<u8>;
}

pub struct Sha3;
pub struct Sha2;

impl RoundFunction for Sha3 {
    fn apply(input: &[u8], key: &[u8]) -> Vec<u8> {
        sha3_256(&[input, key].concat())
    }
}

impl RoundFunction for Sha2 {
    fn apply(input: &[u8], key: &[u8]) -> Vec<u8> {
        sha2_256(&[input, key].concat())
    }
}
