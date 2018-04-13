
## The Imposters
The manufacturer has figured out someone is using SCA on their keyfobs. They have pushed out a patch for their keyfobs changing the AES implementation. The actual AES seems to be hidden inside a number of fake AES operation. Can you still get the key?

The device expects 18 bytes of input: the first byte should be 0xAE (for encryption) followed by 16 bytes of data, followed by a newline.

## Initial Analysis
The fact that this is described as an "update" means it might still be masked. Testing... the same plaintext encrypts to the same ciphertext across reboots. Therefore, not randomly masked.

We did a capture, I count about 15 "aes blocks", so the it's clear what's going on. Hopefully input correlation is our tool of the day.

## Tracing
We gathered some 1200 traces and prepared them as before. The alignments produced was weak, and we didn't get correlations.

## Hardware
We've tried upping the trace count to 100k, and doing expansive SBox and MixColumn based attacks. We also re-ran the IKM attack to make sure we had the parameters correct. With our setup, we can mount that two-round attack with roughly 60 traces. There's no way we need more than 100k to get The Imposters.

However, analysis of Car Key Fob Hardware Backdoor traces showed a very similar pattern, that we think is likely hardware AES. The theory is that the distinctive block/block/small-block/block pattern we see is actually:
	* loading the 16-byte AES key
	* loading the plaintext
	* doing the HW AES routine
	* reading out the ciphertext

The data correlations and timings all line up for this. Assuming it's the case, we then have 16 hardware AES operations, of which 15 are imposters, and one is real. We can easily identify the real one by using data correlations. Also, we note that which operation has correlations varies per reset. Next step: mount a hardware AES attack on the identified operation.

References:
https://wiki.newae.com/Tutorial_A6_Replication_of_Ilya_Kizhvatov%27s_XMEGA%C2%AE_Attack
http://www.iacr.org/phds/106_ilyakizhvatov_physicalsecuritycryptographica.pdf

