# jacopone-lib
Provides a Rust implementation of Jacopone encryption algorithm

Jacopone is based on a Feistel network where the round function in Sha3. The block size is 256 bits and the only
mode of operation currently supported is CTR. The nonce is 60 byte long and the counter is 64 bits.
The key lenght should be 256 bits. 

