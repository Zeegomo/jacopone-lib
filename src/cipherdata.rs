use std::sync::Arc;
use super::jacopone::hash;

pub struct CipherData{
    message: Arc<Vec<u8>>,
    key: Arc<Vec<u8>>,
    nonce: Arc<Vec<u8>>,
    counter: u64,
    round_keys: Arc<Vec<Vec<u8> > >,
}

impl CipherData {

    ///Create new references to message, key, nonce, and counter and store them in CipherData
    pub fn new (message: Vec<u8>, key: Vec<u8>, nonce: Vec<u8>, counter: u64) -> CipherData {
        assert_eq!(nonce.len(), 60, "invalid nonce len: {}. required: {}",nonce.len(), 60);
        assert_eq!(key.len(), 32, "invalid key len: {}. required: {}", key.len(), 32);
        let round_keys = CipherData::generate_round_keys(&key);
        CipherData {message: Arc::new(message), key: Arc::new(key),
            nonce: Arc::new(nonce), counter: counter ,round_keys: Arc::new(round_keys)}
    }

    ///Clone the references
    pub fn clone(other: &CipherData) -> CipherData {
        CipherData {message: Arc::clone(&other.message), key: Arc::clone(&other.key),
            nonce: Arc::clone(&other.nonce), counter: other.counter, round_keys: Arc::clone(&other.round_keys)}
    }


    ///Return references to portions of original message and different counter
    ///
    ///new message is a reference from start to end block of other.message
    ///
    ///new counter is other.counter incremented by end 
    pub fn clone_slice(other: &CipherData, start: usize, end: usize) -> CipherData {
        CipherData {message: Arc::new(other.message[start * 64 .. end * 64].to_vec()), key: Arc::clone(&other.key), 
            nonce: Arc::clone(&other.nonce), counter: other.counter + start as u64, round_keys: Arc::clone(&other.round_keys)}
 
    }

    fn generate_round_keys(key: &[u8]) -> Vec<Vec<u8>> {
        vec![hash(key, "11".as_bytes()), hash(key, "22".as_bytes()),
            hash(key, "33".as_bytes()), hash(key, "44".as_bytes())]
    }

    pub fn get_message(&self) -> &Arc<Vec<u8>> {
        &self.message
    }

    pub fn get_key(&self) -> &Arc<Vec<u8>> {
        &self.key
    }

    pub fn get_nonce(&self) -> &Arc<Vec<u8>> {
        &self.nonce
    }

    pub fn get_counter(&self) -> u64 {
        self.counter
    }

    pub fn get_round_keys(&self) -> &Arc<Vec<Vec<u8>>>{
        &self.round_keys
    }
    
}