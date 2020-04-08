use crate::cipher_mode::{CipherMode, ModeCTR};
use crate::feistel::{Dummy, KeyScheduler, RoundFunction, Sha3, KEY_SIZE};
use std::marker::PhantomData;

pub struct Jacopone<C: CipherMode<R, K>, R: RoundFunction, K: KeyScheduler> {
    _marker: PhantomData<(C, R, K)>,
}

impl Jacopone<ModeCTR, Sha3, Dummy> {
    pub fn default() -> Self {
        Jacopone {
            _marker: PhantomData::<(ModeCTR, Sha3, Dummy)>,
        }
    }
}

impl<C: CipherMode<R, K>, R: RoundFunction, K: KeyScheduler> Jacopone<C, R, K> {
    pub fn new() -> Self {
        Jacopone {
            _marker: PhantomData::<(C, R, K)>,
        }
    }
}

impl<C: CipherMode<R, K>, R: RoundFunction, K: KeyScheduler> Jacopone<C, R, K> {
    pub fn encrypt(&self, message: &mut [u8], key: &[u8], nonce: &[u8]) {
        assert_eq!(key.len(), KEY_SIZE);
        C::encrypt(message, key, nonce);
    }
    pub fn decrypt(&self, ciphertext: &mut [u8], key: &[u8], nonce: &[u8]) {
        assert_eq!(key.len(), KEY_SIZE);
        C::decrypt(ciphertext, key, nonce);
    }
}
