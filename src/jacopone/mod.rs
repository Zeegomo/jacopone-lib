mod thread;
use self::thread::{ParallelThread, FinalThread};
pub use self::thread::hash;
use super::cipherdata::*;


///enviroment for encryption and decryption
pub struct Jacopone{
    parallel_threads: ParallelThread,
}

impl Jacopone {

    ///create a jacopone enviroment to encrypt/decrypt using thread_count threads
    /// ```
    /// use jacopone::*;
    /// let jacopone = Jacopone::new(4);
    /// ```
    pub fn new(thread_count: u8) -> Jacopone {
        Jacopone {parallel_threads: thread::ParallelThread::new(thread_count)}
    }


    /// encrypt given CipherData
    ///
    /// ```
    /// use jacopone::*;
    /// let jacopone = Jacopone::new(4);
    /// let message = "i'm not a safe algorithm".as_bytes().to_vec();
    /// //I'm sorry, it has to be 60 bytes long
    /// let nonce = vec![1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
    ///     0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0];
    /// let key = vec![12,45,8,43,1,2,65,9,1,4,7,9,1,9,3,5,2,4,9,4,1,2,6,9,1,3,6,9,1,9,4,6];
    /// let counter = 42;
    ///
    /// let data = CipherData::new(message, key, nonce, counter);
    ///
    /// let ciphertext = jacopone.encrypt(data);
    /// ```
    pub fn encrypt(&self, data: CipherData) -> Vec<u8> {
        
        //parallel encryption/decryption
        let mut ciphertext = self.parallel_threads.encrypt(CipherData::clone(&data));
        
        //encryption/decryption of last portion
        let ending = FinalThread::finalize_encryption(data);
        ciphertext.extend_from_slice(&ending);
        ciphertext
    }
}