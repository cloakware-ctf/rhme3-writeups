
## It's a Kind of Magic
You managed to get a spare key fob for the car you like. However you want to duplicate it so that you can maintain your access to it. Through extensive reverse engineering, you figure out that the device accepts an input challenge performs AES-128 encryption (or decryption) and returns the response. It is also identified that the device operates on masked input and returns masked output. Extract the key so you can get free rides!

The device expects 18 bytes of input: the first byte should be either 0xAE (for encryption) or 0xAD (for decryption) followed by 16 bytes of data, followed by a newline.

## Side Channel Analysis
Colin O'Flynn (ChipWhisperer) has a pretty good introduction to SCA on YouTube

Breaking AES with ChipWhisperer - Piece of scake (Side Channel Analysis 100)
https://www.youtube.com/watch?v=FktI4qSjzaE&amp=&vl=en
done.

Introduction to Side-Channel Power Analysis (SCA, DPA)
https://www.youtube.com/watch?v=OlX-p4AGhWs
bookmark: 37:01

Tutorial: Breaking AES (Straightforward)
http://www.newae.com/sidechannel/cwdocs/tutorial.html
http://wiki.newae.com/CW308T-GENERIC#Riscure_CTF_Board
https://wiki.newae.com/Main_Page

Piece of scake (and other write-ups)
https://insomnihack.ch/wp-content/uploads/2017/04/AM-ESF-rhme2.pdf
	* contains an image of Hydrabus's CW->RHME3 setup
	* and a bunch of countermeasure and counter-countermeasures

## Notes
    * CW takes 3V, make sure
    * Feed the CW the same clock the target gets
    * Setup CW to the driving input of the target (serial over USB)

## Plaintext / Ciphertext
Encrypting:
00000000  ae 30 31 32  33 34 35 36  37 38 39 61  62 63 64 65  │·012│3456│789a│bcde│
00000010  66 0a                                               │f·│
Result:
00000000  28 35 13 f7  ef 59 60 f7  95 64 8e 06  b2 f9 0b 9f  │(5··│·Y`·│·d··│····│
Decrypting:
00000000  ad 28 35 13  f7 ef 59 60  f7 95 64 8e  06 b2 f9 0b  │·(5·│··Y`│··d·│····│
00000010  9f 0a                                               │··│
Result:
00000000  30 31 32 33  34 35 36 37  38 39 61 62  63 64 65 66  │0123│4567│89ab│cdef│




## Setting Up the ChipWhisperer
Ben soldered the correct headers on the target. I plugged them in and ran the test scripts.

### Test Scripts
	* Glitch line is not connected
	* Random errors with some of them
	* reverted to 3.5.3 and tried again
		-> AES test script worked!

### Tutorials
B1
	* the tutorials are for 4.0.0-alpha
	* B1 just worked, I followed the directions and it paid out.
B2
	* just worked, kinda cool
B3
	* worked, and taught a lot about basic GUI concerns
B5
	* worked, with effort, things are coming together

A1
	* requires hardware I don't have
A5
	* first half works, I'm not sure how to resynchronize traces

### Scake
[https://insomnihack.ch/wp-content/uploads/2017/04/AM-ESF-rhme2.pdf]
	* not enough details, images from ?other? teams
	* useless

[https://github.com/hydrabus/rhme-2016/tree/master/SideChannelAnalysis]
	* possibly multiple revisions of the rhme2 board
	* hydrabus make a custom board and transferred the chip to it

[https://www.balda.ch/posts/2017/Mar/01/rhme2-writeup/#side-channel-analysis]
	* remove all decoupling capacitors
	* add 10 Ohm resisitor on 5V pin, and power via that
	* get a programmatical connection to RX/TX, 
	* references: [http://wiki.newae.com/CW308T-GENERIC#Riscure_CTF_Board]
		* has a pretty clear example, wiring:
		* VIN, RX, TX, GND
		* looks like one chip-pin is wired to D6
		* wires to two other chip-pins
		* 

### Wiring:
If I set the CW to `connection` type `NewAE USB (CWLite/CW1200)` then
	* we emit on TARG1:TX
	* we expect a response on TARG2:RX
	* baud works fine
If I set the CW to `connection` type `ChipWhisperer` then
	* I don't see output.


## Redux: Setting Up the ChipWhisperer
Ben did an awesome soldering/wiring job, and we have a SCA-in-a-box.

Issues:
	* system serial only supports 19200 and 38400 -> edited source to add 115200
	* protocol format defaults to 'hex' -> set to 'bin'
	* ... crap, it's amateur hour here...

## Redux: Riscure Inspector Tool
We were having endless issues with the VCC shunt, so we decided to switch to a GND shunt. Also, we changed almost every other part of the tool-chain.

Current setup:
	* RHme3 with GND shunt.
	* a JTagulator connected to the RHme3's TX pin, set to trigger on every '0x0a' character, and drop its CH0 line for 20ms.
	* A Picoscope 3206D, A line connected to the GND shunt, Ext line on the JTagulator's CH0 line.
	* Riscure's Inspector tool, with a custom script to send the requests over serial after sanitizing any '0x0a' characters out of the ciphertext.

Based on Telegram chatter, we decided to attack the input to AES decrypt. After gathering a bunch of samples, fixing bugs, and tuning the process, we settled in for a major run.

Acquisition and processing:
	* 2500 samples, at 500MHz, for 20ms, at a negative offset of -7ms from the trigger.-
	* Trim to just the first round + margins
	* Low-pass filter, weight: 4
	* Sync-resample to 32MHz
	* Elastic align, radius: 350, window: 0

That got us very solid correlations on 15 of the 16 masked-round-key bytes. Theory time.

Theory:
Because the first/last thing AES does is AddRoundKey, we can consider it to be performing a regular AES operation, but with a modified key-schedule, in which the first and last round key have been masked. Therefore, in order to extract the real key, we perform a second-round attack, (by setting the tool into AES-256 mode), to extract the penultimate round key, which is unmasked. Then we'll run it through a Rjindael key-schedule reverser, and get the key.

So, we flipped the tool into AES-256 mode, and gathered some correlations on the next round. As we should have expected, we got solid correlations on 12 of 16 round sub-keys. Since we can't test keys (we don't know either mask, and even if we got the first one, we'd still need to a bunch of analysis to get the last one), we need high confidence.

This produced two guesses:
	1. c1136b3b6705324d2c3390e029756f6b
	2. c3935a08927c3e7812a09d323e20dd94
Neither worked.

This leaves two options:
	1. try to firm up byte 16
	2. do the whole thing again, and try to get the remaining four key bytes

On path 1, we did a bunch of trace preprocessing before we did the analysis. Time to try a different set. The first-order analysis told us the position the key byte correlations were found, and they were all clustered around a few thousand samples, so trim down to just that (plus margin). Skip the low-pass and resample, and go straight to elastic align. Despite the higher sample count, the tool was able to do it in only an hour or so.

Further testing showed that sub key byte 16 consistently did not correlate. We suspect that this is a bug in the challenge. We switched to a last-round attack which worked perfectly. We got the 2nd round key from that and used the key schedule reverser to get the key. Solved.

```
Your key is: 2c66704041a085fb735fc7013f5783ac
```
