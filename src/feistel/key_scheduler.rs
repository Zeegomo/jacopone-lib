use super::{KEY_SIZE, NUM_ROUNDS};
use std::convert::TryInto;

pub trait KeyScheduler {
    fn get_keys(key: &[u8]) -> [[u8; KEY_SIZE]; NUM_ROUNDS];
}

pub struct Dummy;

impl KeyScheduler for Dummy {
    fn get_keys(key: &[u8]) -> [[u8; KEY_SIZE]; NUM_ROUNDS] {
        let arr: [u8; 32] = key.try_into().expect("Something went wrong");
        [arr, arr, arr, arr]
    }
}
