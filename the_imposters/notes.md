
## The Imposters
The manufacturer has figured out someone is using SCA on their keyfobs. They have pushed out a patch for their keyfobs changing the AES implementation. The actual AES seems to be hidden inside a number of fake AES operation. Can you still get the key?

The device expects 18 bytes of input: the first byte should be 0xAE (for encryption) followed by 16 bytes of data, followed by a newline.

## Initial Analysis
The fact that this is described as an "update" means it might still be masked. Testing... the same plaintext encrypts to the same ciphertext across reboots. Therefore, not randomly masked.

We did a capture, I count about 15 "aes blocks", so the it's clear what's going on. If there are imposter rounds of aes in this trace, there cannot be more than 6, since 10 rounds are needed in most software implementations of aes. Hopefully input correlation is our tool of the day for determining the first round. 

## Tracing
We gathered some 1200 traces and prepared them as before. The alignments produced was weak, and we didn't get correlations.
In fact, we found our input and output corrolations were right next to each other at about round 8! What is going on?

## Hardware
We've tried upping the trace count to 100k, and doing expansive SBox and MixColumn based attacks. We also re-ran the IKM attack to make sure we had the parameters correct. With our setup, we can mount that two-round attack with roughly 60 traces. There's no way we need more than 100k to get The Imposters.

However, analysis of Car Key Fob Hardware Backdoor traces showed a very similar pattern, that we think is likely hardware AES. The theory is that the distinctive block/block/small-block/block pattern we see is actually:
* loading the 16-byte AES key
* loading the plaintext
* doing the HW AES routine
* reading out the ciphertext

The data correlations and timings all line up for this. Assuming it's the case, we then have 16 hardware AES operations, of which 15 are imposters, and one is real. We can easily identify the real one by using data correlations. Also, we note that which operation has correlations varies per reset. Next step: mount a hardware AES attack on the identified operation.

References:
* https://wiki.newae.com/Tutorial_A6_Replication_of_Ilya_Kizhvatov%27s_XMEGA%C2%AE_Attack
* http://www.iacr.org/phds/106_ilyakizhvatov_physicalsecuritycryptographica.pdf

## Installing and Configuring Jlsca
  1. Go to [Julia Install instruction](https://julialang.org/downloads/platform.html)
  2. Get and install julia v6.0 or higher
```julia
Pkg.clone("https://github.com/Riscure/Jlsca")
Pkg.add("IJulia")
Pkg.add("PyPlot")
Pkg.add("PyCall")
using IJulia; notebook()
```



## Results
The class of attack used was based upon Ilya's work referenced above.  
When Ilya's attacks were fully operational It worked perfectly on the example traces, the imposters... not so much.


Candidates:
64MHz, flipHW, GM, 3000:4000
3fc0f84cd7d584e497b2bb05e5934598
3fc0fcd2e44e8ca9d056609b52ef44b2
3fc09ba5629e20ce634dc338a06bbc4a
3fc0d0ee29d56b852806b843db10c731

### Hunting for targets
I now believe that what sort of correlations appear differ from what Ilya saw.  
I am hunting for better models.  
Note: because previous keybyte and data are Null for the first target, it's an easier thing to hit...

```python
(nowData ⊻ guess) ⊻ a.sbox[(nowData ⊻ guess)+1]
rank:   1, candidate: 0x00, peak: 0.145686 @ 1835

(prevData ⊻ previousKeyByte) ⊻ (nowData ⊻ guess)
rank:   1, candidate: 0xc0, peak: 0.130728 @ 1918
rank:   1, candidate: 0xc0, peak: 0.527390 @ 1684
rank:   1, candidate: 0xc0, peak: 0.447334 @ 1726

(prevData ⊻ previousKeyByte) ⊻ (nowData ⊻ guess) ⊻ a.sbox[(nowData ⊻ guess)+1]
rank:   1, candidate: 0x00, peak: 0.145686 @ 1835
```

Analysis:
- the sbox hit is too huge to ignore... but only catches one keybyte
- ...

### Reasonable Hits:
(nowData ⊻ guess) ⊻ a.sbox[(nowData ⊻ guess)+1]
- Result: 0071af0e4d49b430d9d08c46403d2649
- super strong hit on first keybyte, garbage on rest
- retried with forced first byte: 00, c0, a3

(nowData ⊻ guess) ⊻ a.sbox[(nowData ⊻ guess)+1] ⊻ a.sbox[(prevData ⊻ previousKeyByte)+1]
- Result: a31002ef5bcd05ffa4da9a8d6f6dc1b0
- reasonable hits on multiple bytes

(nowData ⊻ guess) ⊻ (prevData ⊻ previousKeyByte)
- this is Ilya's target. Works flawlessly for his sample set.
- Result: c0c0c0c0c0c0c0c0c080808080808080
- above: pretty solid hits, must be noisish
- Result: 3f8cafd88968afd9946bbef38d72084c
- above: with many 100k traces, flipHW and progressive on. That looks keyish.
- Result: ???
- above: with many 100k traces, HW and progressive on. That looks keyish.

(nowData ⊻ guess) ⊻ (prevData ⊻ previousKeyByte) ⊻ a.sbox[(nowData ⊻ guess)+1]
- Result: 003e01336712f0264e439db1cd5569df
- some hits, mostly noise...

(nowData ⊻ guess) ⊻ (prevData ⊻ previousKeyByte) ⊻ a.sbox[(nowData ⊻ guess)+1]
- Result: 80...
- hit is pretty solid. Actually on (data ⊻ 0x00 ⊻ 0x00 ⊻ 0x80 ⊻ a.sbox(data^guess))
- which is interesting, because it suggests a previousByte of 80 for the first


Analysis:
* SBox In XOR Out gives a good hit for the first
  - But crap for subsequent. Maybe one of the "guess"s should be prev?
  - might be bogus, didn't find it on 100k trace.
* ARK XOR last-ARK gives solid, across the board hits
  - but BS key.
  - forcing progressive fixes that, gives reasonable offsets, key is invalid
* Note that for ARK XOR lARK, the first hit is weirdly positioned
  - might be because of an odd "previous"
  - obvious candidate before is 4f

## Known Key Attacks
Since we couldn't get the key to fall out, we tried another tack. We wrote our own version of the challenge for an XMEGA 128 A3U processor we had, and went hunting for known-key on it. We found that the key bytes we correlated diagonally. A little math later, we found they were being processed in ShiftRows order. 

Armed with that knowledge, we were able to mount an attack that worked on our known-key version, and which transferred to the RHme3 target. Success.
