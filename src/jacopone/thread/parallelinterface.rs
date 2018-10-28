use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;

pub struct ParallelInterface<T> {
	tx: Vec<Sender<Vec<T> > >,
	rx: Vec<Receiver<Vec<T> > >,
}

impl<T> ParallelInterface<T> {

	pub fn new(n: u8) -> ParallelInterface<T>{
		let mut tx = Vec::new();
		let mut rx = Vec::new();
		for _i in 0..n {
        	let (tx1, rx1) = mpsc::channel();
        	tx.push(tx1);
        	rx.push(rx1);
    	}
    	ParallelInterface {tx: tx, rx: rx}
	}

	pub fn get_tx(&self, n: u8) -> Sender<Vec<T>> {
		assert!(n < self.tx.len() as u8);
		mpsc::Sender::clone(&self.tx[n as usize])
	}

	//pub fn send(n: u8, )
	
	pub fn concat(&self, active_threads: u8) -> Vec<T>  where T: Clone{
		let mut blocks = Vec::new();
    	for i in 0..active_threads as usize {
            blocks.push(self.rx[i].recv().unwrap()); 
    	}
    	let mut ciphertext = Vec::new();
    	for i in 0..active_threads as usize {
            ciphertext.extend_from_slice(&blocks[i]);
    	}
    	ciphertext
	}

}