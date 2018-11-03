# jacopone-lib
[![Build Status](https://travis-ci.org/Zeegomo/jacopone-lib.svg?branch=master)](https://travis-ci.org/Zeegomo/jacopone-lib)
[![Crates.io](https://img.shields.io/crates/v/jacopone.svg)](https://crates.io/crates/jacopone)

Rust implementation of Jacopone encryption algorithm

### Jacopone
Jacopone is a block cipher designed by me, spoiler alert: **not safe**

Jacopone is based on a 4-round Feistel network with Sha3 as round function. The block size is 512 bits and the 
key length is 256 bits. The only cipher mode of operation currently supporter is CTR and the nonce is required to be 60 bytes.
Round keys are derived from a sha-3 hash of (master key | kth byte of master key) for each of the 4 rounds.
  
This construction scheme, still subject to change, is based on work by M. Luby and C. Rackoff and should be, at least theoretically,
not obviously wrong.



