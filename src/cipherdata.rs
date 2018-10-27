use std::sync::Arc;

pub struct CipherData{
    pub message: Arc<Vec<u8>>,
    pub key: Arc<Vec<u8>>,
    pub nonce: Arc<Vec<u8>>,
    pub counter: u64,
}

impl CipherData {

    ///Create new references to message, key, nonce, and counter and store them in CipherData
    pub fn new (message: Vec<u8>, key: Vec<u8>, nonce: Vec<u8>, counter: u64) -> CipherData {
        assert_eq!(nonce.len(), 60, "invalid nonce len: {}. required: {}",nonce.len(), 60);
        assert_eq!(key.len(), 32, "invalid key len: {}. required: {}", key.len(), 32);
        CipherData {message: Arc::new(message), key: Arc::new(key), nonce: Arc::new(nonce), counter: counter}
    }

    ///Clone the references
    pub fn clone(other: &CipherData) -> CipherData {
        CipherData {message: Arc::clone(&other.message), key: Arc::clone(&other.key), nonce: Arc::clone(&other.nonce), counter: other.counter}
    }

    ///Return references to portions of original message and different counter
    ///
    ///new message is a reference from start to end block of other.message
    ///
    ///new counter is other.counter incremented by end 
    pub fn clone_slice(other: &CipherData, start: usize, end: usize) -> CipherData {
        CipherData {message: Arc::new(other.message[start * 64 .. end * 64].to_vec()), key: Arc::clone(&other.key), nonce: Arc::clone(&other.nonce), counter: other.counter + start as u64}
 
    }
}