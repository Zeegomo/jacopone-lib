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


    ///Return references to portions of original message and different counter. New message is a reference from start to end blocks of other.message
    /// while new counter is equals to other.counter incremented by end
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

#[cfg(test)]
mod tests {
    use crate::jacopone::*;
    use crate::CipherData;

    #[test]
    #[should_panic]
    fn assert_invalid_key_1(){
        let message = "aaaaaaaaaa".as_bytes().to_vec();
        let nonce = vec![1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0];
        let key = vec![3,4,5,6,7,8,9,0,9,8,7,6,5,4,3,2,1,2,3,4,5,6,7,8,9,0,9,8,7,3,5];
        CipherData::new(message, key, nonce, 453);
    }

    #[test]
    #[should_panic]
    fn assert_invalid_key_2(){
        let message = "aaaaaaaaaa".as_bytes().to_vec();
        let nonce = vec![1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0];
        let key = vec![2,3,4,5,6,7,8,9,0,9,8,7,6,5,4,3,2,1,2,3,4,5,6,7,8,9,0,9,8,7,3,54,1,2,3,4,3];
        CipherData::new(message, key, nonce, 453);
    }

    #[test]
    #[should_panic]
    fn assert_invalid_key_nonce_1(){
        let message = "aaaaaaaaaa".as_bytes().to_vec();
        let key = vec![12,45,98,43,1,32,65,99,1,43,76,98,12,98,43,65,12,45,98,43,1,32,65,99,1,43,76,98,12,98,43,65];
        let nonce = vec![1,2,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0];
        CipherData::new(message, key, nonce, 453);
    }

    #[test]
    #[should_panic]
    fn assert_invalid_key_nonce_2(){
        let message = "aaaaaaaaaa".as_bytes().to_vec();
        let key = vec![12,45,98,43,1,32,65,99,1,43,76,98,12,98,43,65,12,45,98,43,1,32,65,99,1,43,76,98,12,98,43,65];
        let nonce = vec![99,4,43,12,43,65,23,65,87,1,98,9,8,7,6,5,4,3,2,1,54,0,87,98,1,45,87,32,8,34,2,34,34,76,32,176,87,231,22,201,234,63,76,9,76,87,1,3,4,8,54,32,13,98,56,44,33,76,54,34,65];
        CipherData::new(message, key, nonce, 453);
    }
}
