use super::RoundFunction;
use crate::utils::xor;
use crunchy::unroll;

pub const NUM_ROUNDS: usize = 4;
pub const BLOCK_SIZE: usize = 64;
pub const KEY_SIZE: usize = 32;

pub fn block_encrypt<R: RoundFunction>(message: &mut [u8], key: &[[u8; KEY_SIZE]; NUM_ROUNDS]) {
    assert_eq!(message.len(), BLOCK_SIZE);

    unroll! {
        // using literal to unroll
        for i in 0..4 {
            feistel_round::<R>(message, &key[i]);
            swap(message);
        }
    }
}

fn feistel_round<R: RoundFunction>(block: &mut [u8], key: &[u8; KEY_SIZE]) {
    let (left, right) = block.split_at_mut(BLOCK_SIZE / 2);
    xor(left, R::apply(right, key).as_ref());
}

fn swap(block: &mut [u8]) {
    let (left, mut right) = block.split_at_mut(BLOCK_SIZE / 2);
    left.swap_with_slice(&mut right);
}
