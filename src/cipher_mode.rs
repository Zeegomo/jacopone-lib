use crate::feistel::{block_encrypt, KeyScheduler, RoundFunction, BLOCK_SIZE};
use crate::padding::Padder;
use crate::utils::{sha3_512, xor};

// Represents Block Cipher Mode
pub trait CipherMode<R: RoundFunction, K: KeyScheduler, P: Padder> {
    fn encrypt(
        &self,
        message: &mut Vec<u8>,
        key: &[u8],
        nonce: Option<&[u8]>,
        function: R,
        ks: K,
        pad: P,
    );
    fn decrypt(
        &self,
        message: &mut Vec<u8>,
        key: &[u8],
        nonce: Option<&[u8]>,
        function: R,
        ks: K,
        pad: P,
    );
}

pub enum Mode {
    CTR,
    ECB,
}

impl<R: RoundFunction, K: KeyScheduler, P: Padder> CipherMode<R, K, P> for Mode {
    fn encrypt(
        &self,
        message: &mut Vec<u8>,
        key: &[u8],
        nonce: Option<&[u8]>,
        function: R,
        ks: K,
        pad: P,
    ) {
        match self {
            Mode::CTR => ModeCTR::encrypt(message, key, nonce, function, ks),
            Mode::ECB => ModeECB::encrypt(message, key, nonce, function, ks, pad),
        }
    }
    fn decrypt(
        &self,
        message: &mut Vec<u8>,
        key: &[u8],
        nonce: Option<&[u8]>,
        function: R,
        ks: K,
        pad: P,
    ) {
        match self {
            Mode::CTR => ModeCTR::decrypt(message, key, nonce, function, ks),
            Mode::ECB => ModeECB::decrypt(message, key, nonce, function, ks, pad),
        }
    }
}

pub struct ModeCTR;
pub struct ModeECB;

impl ModeCTR {
    fn blocks_num(len: usize) -> usize {
        (len + BLOCK_SIZE - 1) / BLOCK_SIZE
    }

    // Always produce 64 byte output
    fn get_block(nonce: &[u8], cnt: u64) -> Vec<u8> {
        assert_eq!(nonce.len(), 56);
        [nonce.to_vec(), cnt.to_le_bytes().to_vec()].concat()
    }

    fn simmetric<R: RoundFunction, K: KeyScheduler>(
        message: &mut [u8],
        key: &[u8],
        nonce: &[u8],
        function: R,
        ks: K,
    ) {
        let round_keys = ks.get_keys(key);
        let blocks_num = ModeCTR::blocks_num(message.len());

        let mut nonce = sha3_512(nonce);
        nonce.truncate(56);

        let stream = (0..blocks_num)
            .map(|i| {
                let mut blk = Self::get_block(&nonce, i as u64);
                block_encrypt(&mut blk, &round_keys, function);
                blk.to_vec()
            })
            .flatten()
            .collect::<Vec<u8>>();
        //stream.resize(message.len());
        xor(message, &stream);
    }

    fn encrypt<R: RoundFunction, K: KeyScheduler>(
        message: &mut Vec<u8>,
        key: &[u8],
        nonce: Option<&[u8]>,
        function: R,
        ks: K,
    ) {
        Self::simmetric::<R, K>(
            message,
            key,
            nonce.expect("Nonce is required in CTR mode"),
            function,
            ks,
        )
    }
    fn decrypt<R: RoundFunction, K: KeyScheduler>(
        message: &mut Vec<u8>,
        key: &[u8],
        nonce: Option<&[u8]>,
        function: R,
        ks: K,
    ) {
        Self::simmetric::<R, K>(
            message,
            key,
            nonce.expect("Nonce is required in CTR mode"),
            function,
            ks,
        )
    }
}

impl ModeECB {
    fn simmetric<R: RoundFunction, K: KeyScheduler>(
        message: &mut [u8],
        key: &[u8],
        rev: bool,
        function: R,
        ks: K,
    ) {
        let mut round_keys = ks.get_keys(key);
        if rev {
            round_keys.reverse();
        }

        message
            .chunks_mut(BLOCK_SIZE)
            .for_each(|chunk| block_encrypt(chunk, &round_keys, function));
    }

    fn encrypt<R: RoundFunction, K: KeyScheduler, P: Padder>(
        message: &mut Vec<u8>,
        key: &[u8],
        nonce: Option<&[u8]>,
        function: R,
        ks: K,
        padder: P,
    ) {
        assert!(nonce.is_none(), "Nonce is not supported in ECB mode");
        padder.pad(message, BLOCK_SIZE as u8);
        Self::simmetric(message, key, false, function, ks);
    }
    fn decrypt<R: RoundFunction, K: KeyScheduler, P: Padder>(
        message: &mut Vec<u8>,
        key: &[u8],
        nonce: Option<&[u8]>,
        function: R,
        ks: K,
        padder: P,
    ) {
        assert!(nonce.is_none(), "Nonce is not supported in ECB mode");
        Self::simmetric(message, key, true, function, ks);
        padder.unpad(message);
    }
}
