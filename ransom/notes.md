
## Ransom
In theory, this firmware mod was supposed to give you 30% extra horsepower and torque. In reality, it's something different.

## Reversing Functions
### main_313
Init loop calls sub_2b2() 8x times
	- 7f00 -> e238
	- iterator is Y[1:2]
	- stores result in Y + 9 + 2*iterator
	-> looks like keygen for unlock code

data 0x2000  38 e2 a0 08 40 06 04 08 02 20 b0 09 60 06 40 80  8â .@.... °.`.@€
data 0x2010  0a 20 25 30 32 58 00 0a 0a 59 6f 75 72 20 63 61  . %02X...Your ca

### usart_recv_byte
function usart_recv_byte (aka sub_59c) {
	IN: serial address in rx24
	OUT: a byte in r24
	Y[1:2] = rx24
	do {
		ZL,ZH = rx24 = Y[1:2]
		rx24 = *Z (get serial address)
		ZL,ZH = rx24
		r24 = Z[1] (pretty sure this is "how many bytes pending?")
	} while (r24==0)
	(copy/paste loop contents here, but with r24=Z[0], aka "get the next byte")
	return r24
}

### misc
sub_19d() {
	call sub_769()
	Y[3:4] = rx24
}
sub_769() {
	// looks a lot like 
	lazy call sub_713()
	return rx24 = sub_909(0x2221)
}
sub_909(rx24)
	sub_77e(rx24)
	return sub_897(rx24)
}

### 77e
sub_77e(rx24) {
	At opening of 0x77e, Z[2221] vector is:
		41 52 69 75 1e 6a 2a 22 16 f4 7a ec b9 86 26 89
	After completion, Z[2221] vector is: (aka start 0x897)
		 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
		1e 6a 2a 22 16 f4 7a ec db ac 0e 33 3e 91 ff 00
		[0]	0x222a6a1e
		[1]	0xec7af416
		[2]	0x330eacdb
		[3]	0x00ff913e
		[4]	0xae58eb97
		[5]	0x00000000
		[6]	0x65223bff
		[7]	0x00000000
}

### 897
sub_897(vector) {
	Z=vector
	YD[1] = ZD[2] >> 8 + ZD[0]
	YD[0] = ZD[3] ^ YD[1]
	rax18 = (YD[1] & 1) ? 0xff : 0x00
	Y[0] = (ZD[6] & rax18) ^ YD[0]
	rax24 = Y[0]
	return rx24
	/* note: what we care about is even/odd
	 * and that's wierd...
	 * consider Z12 & 1
	 * consider Z24 & 1, but only if Z9+Z0 is odd
	 * xor two above lines together
}

### 1c7
<code c>
sub_1c7() {
	IN: r22=suspected unlock code; r24=my chosen code; r20=my strlen
	for (i=length; i>=0; i--) {
	    //       1:2     3:4    5   6:7   9:8  10:11
		// Y = chosen, unlock, 00, arg0, arg1, arg2==i
		sub_19a()
	}
	x = Y[1:2]++
	y = Y[3:4]++
	r25 = x^y | length? //where length==0
	return 0 if r25==0
	else return 1



}
</code>

### xrefs
sub_909 is called with 0x2221
	- which is random bytes, populated from somewhere..
	- 7c b2 97 17 57 04 7d 2d 95 b4 5f 9c 64 7c 2e 5a
	- 4d 14 4b f2 65 78 e5 5f ca e3 8a 6c 9c 13 6d 0d
	- mysterious Z-vector
	-> sub_77e(Z)
	-> sub_897(Z)
sub_713
	- 3418
	- 1826
	- 223b
	- 2221
	-> sub_98a

## Dynamic Work
Goals:
	- find userid, make sure it matches

breakpoints:
	0x407: userid
<code>
data 0x2170  79 21 0a 00 00 54 6f 20 67 65 74 20 79 6f 75 72  y!...To get your
data 0x2180  20 63 61 72 20 62 61 63 6b 2c 20 73 65 6e 64 20   car back, send 
data 0x2190  79 6f 75 72 20 75 73 65 72 20 49 44 3a 0a 46 46  your user ID:.FF
data 0x21A0  46 46 46 46 46 46 46 46 46 46 46 46 46 46 0a 00  FFFFFFFFFFFFFF..
</code>
So:
	1. Userid is in NVM: value: ff ff ff ff ff ff ff ff ff ff ff
		- sub_632() copies to 0x3fd4
		-> 11 bytes long!
	2. memcpy tail 8 bytes
		- 0x3fd7 -> 0x3fba
	3. sprintf using "%02x" in sub_268()
		- 0x3fba -> 0x3fc3 (16 bytes, duh) (yes, null terminated)
	* Userid can be found at 0x3fc3 (as a hex string)
	* And should be: 3835320716000D00
		- first three bytes are "852"
	* After init completes, the following bits are lying around:
		- 267EDED9BE5494D85449088FD41F38E2
	* Altering hidden three bytes of userid doesn't change unlock code

Our input code gets written to:
	0x3f78, max 32 bytes, including null terminator

Things to do:
	* NOP 0x1ab (starting at 0x356, because bytes vs words)
	* break on 0x330
		- set  3fd7 to userid
	* break on 0x407
		- watch printf
	* break on 0x42d
		- is the read -> 0x3f78
		- put target text there
		- and skip it

Notes:
	* Calling sub_769() the first time major changes to 0x3f18...0x3f58
		- but that's probably my stack?
	* similarly, there was a change to 0x3f58...0x3f60 before exit
		- more stack
	* again, same thing

## Summary
First we did static analysis, from which we found the serial prints and the serial reads, but we misunderstood the busy-wait code and thought we would need to reverse that. So, instead of doing so, we set up a simulation environment leveraging Atmel Studio 7.

Key Process:
Tools -> Device Programming -> Simulator / ATxmega128A4U
Production file, Save to ELF production file, Flash: <target>.hex
Tick the Flash box
Save

File -> Open -> Open Object File for Debugging
Select the Object File To Debug: <target>.elf

Once that was complete, we noticed that in the simulator, it was printing out a null userid "FFFFFFFFFFFFFFFF". We traced that back to see where it was coming from, and found that in `sub_632()`, it was being read from NVM. Interestingly, 11 bytes were read, but only 8 used. Hoping the other three didn't matter, we overwrote the 8, and let it continue.

The next major stage of initialization used the userid to create a 16 byte random-looking bytestream, which was then sprintf()d into hex and stored on the stack. This looked a lot like a flag to use... no dice. Next, it looked a lot like the ransom-unlock code... worked.

```
Your car is taken hostage by REVENANTTOAD ransomware version DEBUG_a4fae86c.
To get your car back, send your user ID:
3835320716000D00

and $1337 to the following rhme3coin address:
[CENSORED].

Already paid? Then enter the received unlock code here:
267EDED9BE5494D85449088FD41F38E2
It was a pleasure doing business with you.
Your car is now unlocked.
Here is a bonus:
faeeecd45603d9e77d228b3eae2ffc08
Have a nice day!
```

