use super::utils::*;
use super::super::super::cipherdata::*;

pub fn jacopone_encrypt_ctr(data: CipherData) -> Vec<u8> {
    let mut c = data.get_counter();
    let mut ciphertext = Vec::with_capacity(data.get_message().len());
    let start = data.get_start();
    for i in 0..data.get_blocks_len() {
        let block_counter = get_block_counter(data.get_nonce(), & mut c);
        ciphertext.extend_from_slice(&xor(&block_encrypt(&block_counter, data.get_round_keys()), &data.get_message()[64 * i + start.. 64 * i + 64 + start]));
    }
    //let block_counter = get_block_counter(data.get_nonce(), & mut c);
    //ciphertext.extend_from_slice(&xor(&data.get_message()[(data.get_message().len()/64) * 64..], &block_encrypt(&block_counter, data.get_round_keys())));
    ciphertext
}

pub fn block_encrypt(message: &[u8], key: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut ciphertext = message.to_vec();
    
    unroll! {
        for _i in 0..4 {
            ciphertext = feistel_round(&ciphertext, &key[_i]);
            ciphertext = swap(&ciphertext);
        }
    }

    ciphertext
} 

pub fn feistel_round(block: &[u8], key: &[u8]) -> Vec<u8> {
    //&block[0..32] is left part
    //&block[32..] is right part
    let l = &block[0..32];
    let mut l = xor(l, &hash(&block[32..], key));
    l.extend_from_slice(&block[32..]);
    l
}



pub fn get_block_counter(nonce: &[u8], counter: & mut u64) -> Vec<u8> {
    let mut n = nonce.to_vec();
    n.extend_from_slice(&(to_bytes(*counter)));
    *counter = (*counter).wrapping_add(1);
    n  
}


pub fn get_thread_blocks(message_len: usize, thread_count: u8) -> Vec<[u64; 2]>{
    let message_len = message_len as u64;
    let mut partition = Vec::new();
    let mut blocks_index = Vec::new(); 
    let block_num = message_len / 64;
    //if block_num / thread_count  as u64 > 0 {
    for _i in 0..thread_count {
        partition.push(block_num / thread_count as u64);
    }


    let mut res = block_num - (block_num / thread_count as u64) * thread_count as u64;    
    for i in 0..thread_count as usize {
        if res > 0 {
            partition[i] = partition[i] + 1;
            res = res - 1;
        }
    }
    blocks_index.push([0, partition[0]]);
    let mut last = partition[0];
    for i in 1..thread_count as usize {
        blocks_index.push([last, last + partition[i]]);
        last = last + partition[i];
    }
    for i in 0..blocks_index.len() {
        if blocks_index[i][0] == blocks_index[i][1] {
            blocks_index.truncate(i);
            break;
        }
    }

    blocks_index
}