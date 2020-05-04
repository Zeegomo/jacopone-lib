use crate::cipher_mode::CipherMode;
use crate::feistel::{KeyScheduler, RoundFunction, KEY_SIZE};
use crate::padding::Padder;

pub struct Jacopone<C: CipherMode<R, K, P>, R: RoundFunction, K: KeyScheduler, P: Padder> {
    mode: C,
    function: R,
    key_scheduler: K,
    padder: P,
}

impl<C: CipherMode<R, K, P>, R: RoundFunction, K: KeyScheduler, P: Padder> Jacopone<C, R, K, P> {
    pub fn new(mode: C, function: R, key_scheduler: K, padder: P) -> Self {
        Jacopone {
            mode,
            function,
            key_scheduler,
            padder,
        }
    }
}

impl<C: CipherMode<R, K, P>, R: RoundFunction, K: KeyScheduler, P: Padder> Jacopone<C, R, K, P> {
    pub fn encrypt(&self, message: &mut Vec<u8>, key: &[u8], nonce: Option<&[u8]>) {
        assert_eq!(key.len(), KEY_SIZE);
        self.mode.encrypt(
            message,
            key,
            nonce,
            self.function,
            self.key_scheduler,
            self.padder,
        );
    }
    pub fn decrypt(&self, ciphertext: &mut Vec<u8>, key: &[u8], nonce: Option<&[u8]>) {
        assert_eq!(key.len(), KEY_SIZE);
        self.mode.decrypt(
            ciphertext,
            key,
            nonce,
            self.function,
            self.key_scheduler,
            self.padder,
        );
    }
}
