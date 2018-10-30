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
    pub fn new(thread_count: u8) -> Jacopone {
        Jacopone {parallel_threads: thread::ParallelThread::new(thread_count)}
    }


    /// encrypt given CipherData
    ///
    pub fn encrypt(&self, data: CipherData) -> Vec<u8> {
        
        //parallel encryption/decryption
        let mut ciphertext = self.parallel_threads.encrypt(CipherData::clone(&data));
        
        //encryption/decryption of last portion
        let ending = FinalThread::finalize_encryption(data);
        ciphertext.extend_from_slice(&ending);
        ciphertext
    }
}