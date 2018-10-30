mod thread;
use self::thread::{ParallelThread, FinalThread};
pub use self::thread::hash;
use super::cipherdata::*;


///enviroment for encryption and decryption
pub struct Jacopone{
    thread_count: u8,
    final_thread: FinalThread,
    parallel_threads: ParallelThread,
}

impl Jacopone {

    ///create a jacopone enviroment to encrypt/decrypt using thread_count threads
    pub fn new(thread_count: u8) -> Jacopone {
        Jacopone {thread_count: thread_count, final_thread: FinalThread::new(thread_count), parallel_threads: thread::ParallelThread::new(thread_count)}
    }


    /// encrypt given CipherData
    ///
    pub fn encrypt(&self, data: CipherData) -> Vec<u8> {
        let mut ciphertext = Vec::new();

        //parallel encryption/decryption
        if self.thread_count > 0 {
            ciphertext.extend_from_slice(&self.parallel_threads.encrypt(CipherData::clone(&data)));
        }
        
        //encryption/decryption of last portion
        let ending = self.final_thread.finalize_encryption(data);
        ciphertext.extend_from_slice(&ending);
        ciphertext
    }
}