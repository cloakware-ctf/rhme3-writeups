
## The Imposters
The manufacturer has figured out someone is using SCA on their keyfobs. They have pushed out a patch for their keyfobs changing the AES implementation. The actual AES seems to be hidden inside a number of fake AES operation. Can you still get the key?

The device expects 18 bytes of input: the first byte should be 0xAE (for encryption) followed by 16 bytes of data, followed by a newline.

## Initial Analysis
The fact that this is described as an "update" means it might still be masked. Testing... the same plaintext encrypts to the same ciphertext across reboots. Therefore, not randomly masked.

We did a capture, I count about 15 "aes blocks", so the it's clear what's going on. Hopefully input correlation is our tool of the day.

## Tracing
We gathered some 1200 traces and prepared them as before. The alignments produced was weak, and we didn't get correlations.
