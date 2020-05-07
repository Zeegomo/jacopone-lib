use std::iter::repeat;

pub trait Padder: Copy {
    fn pad(&self, message: &mut Vec<u8>, len: u8);
    fn unpad(&self, message: &mut Vec<u8>);
}

#[derive(Clone, Copy)]
pub enum Padding {
    PKCS7,
}

impl Padder for Padding {
    fn pad(&self, message: &mut Vec<u8>, len: u8) {
        PKCS7::pad(message, len);
    }

    fn unpad(&self, message: &mut Vec<u8>) {
        PKCS7::unpad(message);
    }
}

pub struct PKCS7;

impl PKCS7 {
    fn pad(message: &mut Vec<u8>, len: u8) {
        let pl = len as usize - message.len() % len as usize;

        message.extend(repeat(pl as u8).take(pl as usize));
    }

    fn unpad(message: &mut Vec<u8>) {
        if let Some(&last) = message.last() {
            message.truncate(message.len() - last as usize);
        }
    }
}
