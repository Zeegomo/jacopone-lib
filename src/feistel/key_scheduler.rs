use super::{KEY_SIZE, NUM_ROUNDS};
use std::convert::TryInto;
const PBKDF_ITERS: usize = 100000;
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};

pub trait KeyScheduler: Copy {
    fn get_keys(&self, key: &[u8]) -> [[u8; KEY_SIZE]; NUM_ROUNDS];
}

#[derive(Clone, Copy)]
pub enum Scheduler {
    Dummy,
    PBKDF,
}

impl KeyScheduler for Scheduler {
    fn get_keys(&self, key: &[u8]) -> [[u8; KEY_SIZE]; NUM_ROUNDS] {
        match self {
            Scheduler::Dummy => Dummy::get_keys(key),
            Scheduler::PBKDF => PBKDF::get_keys(key),
        }
    }
}

pub struct Dummy;
pub struct PBKDF;

impl Dummy {
    fn get_keys(key: &[u8]) -> [[u8; KEY_SIZE]; NUM_ROUNDS] {
        let arr: [u8; 32] = key.try_into().expect("Something went wrong");
        [arr; NUM_ROUNDS]
    }
}

impl PBKDF {
    fn get_keys(key: &[u8]) -> [[u8; KEY_SIZE]; NUM_ROUNDS] {
        let mut keys = [0 as u8; KEY_SIZE * NUM_ROUNDS];
        let mut output = [[0 as u8; KEY_SIZE]; NUM_ROUNDS];
        pbkdf2_hmac(
            key,
            "".as_bytes(), // we don't need salt as se key should be already strong enough
            PBKDF_ITERS,
            MessageDigest::sha3_256(),
            &mut keys,
        )
        .expect("Could not generate round keys");

        keys.chunks(KEY_SIZE).enumerate().for_each(|(i, chunk)| {
            output[i].copy_from_slice(chunk);
        });
        output
    }
}
