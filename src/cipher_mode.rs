use crate::feistel::{block_encrypt, KeyScheduler, RoundFunction, BLOCK_SIZE};
use crate::utils::{sha3_512, xor};

pub trait CipherMode<R: RoundFunction, K: KeyScheduler> {
    fn encrypt(message: &mut [u8], key: &[u8], nonce: &[u8]);
    fn decrypt(message: &mut [u8], key: &[u8], nonce: &[u8]);
}

pub struct ModeCTR;

impl ModeCTR {
    fn blocks_num(len: usize) -> usize {
        (len + BLOCK_SIZE - 1) / BLOCK_SIZE
    }

    // Always produce 64 byte output
    fn get_block(nonce: &[u8], cnt: u64) -> Vec<u8> {
        assert_eq!(nonce.len(), 56);
        [nonce.to_vec(), cnt.to_le_bytes().to_vec()].concat()
    }

    fn simmetric<R: RoundFunction, K: KeyScheduler>(message: &mut [u8], key: &[u8], nonce: &[u8]) {
        let round_keys = K::get_keys(key);
        let blocks_num = ModeCTR::blocks_num(message.len());

        let mut nonce = sha3_512(nonce);
        nonce.truncate(56);

        let stream = (0..blocks_num)
            .map(|i| {
                let mut blk = Self::get_block(&nonce, i as u64);
                block_encrypt::<R>(&mut blk, &round_keys);
                blk.to_vec()
            })
            .flatten()
            .collect::<Vec<u8>>();
        //stream.resize(message.len());
        xor(message, &stream);
    }
}

impl<R: RoundFunction, K: KeyScheduler> CipherMode<R, K> for ModeCTR {
    fn encrypt(message: &mut [u8], key: &[u8], nonce: &[u8]) {
        Self::simmetric::<R, K>(message, key, nonce)
    }
    fn decrypt(message: &mut [u8], key: &[u8], nonce: &[u8]) {
        Self::simmetric::<R, K>(message, key, nonce)
    }
}
