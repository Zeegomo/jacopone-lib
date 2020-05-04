use crate::utils::{sha2_256, sha3_256};

pub trait RoundFunction: Copy {
    fn apply(&self, input: &[u8], key: &[u8]) -> Vec<u8>;
}

#[derive(Clone, Copy)]
pub enum Function {
    Sha2,
    Sha3,
}

impl RoundFunction for Function {
    fn apply(&self, input: &[u8], key: &[u8]) -> Vec<u8> {
        match self {
            Function::Sha3 => sha3_256(&[input, key].concat()),
            Function::Sha2 => sha2_256(&[input, key].concat()),
        }
    }
}
