
There's a lot of anti-FI and anti-RNG pinning, I'm trying to ignore

In main:
```c
	printf("Welcome to the maintenance interface.");
	read_str_until(Y+20, len:5, "\n");

	if (strcmp(Y+20, "test")) {
		do_test();
	} else if (strcmp(Y+20, "*")) {
		while (1) {
			byte = usart_recv_byte(USART);
			process_star(byte);
			// XXX how do we get out of this???
		}
	} else if (strcmp(Y+20, "risc")) {
		X = 0x200a;
		Z = 0x225e;
		for (rx24 = 298 ; rx24>0; rx24--) { // XXX approximate
			*X++ = *Z++
		}
		X = 0x2134;
		Z = 0x2388;
		for (rx24 = 298 ; rx24>0; rx24--) { // XXX approximate
			*X++ = *Z++
		}
		do_test();
	} else {
		// do nothing
	}
```

So it looks like we need to * ourselves some data, then risc it.

## Reversing
### Variables:
    r17 = a byte
	rx16 = a word r16+r17
	erx = long
	rrx = long long
	
### Fixing String Drefs:
Because we build drefs using comments, stringifying a string changes the name, for example, before it might be `unk_102739`, but after `aFiDetectedPerfor`. That name change breaks the comment-ref.

The following fixes one ref.
```python
MakeRptCmt(ScreenEA(), Name(Dfirst(ScreenEA())))
```

This fixes all refs to the selected block of code
```python
for ea in range(SelStart(), SelEnd()):
	dref = DfirstB(ea)
	while 4294967295 != dref:
		MakeRptCmt(dref, Name(ea))
		dref = DnextB(ea, dref)
```

### sub_17f1()
	prints "ABORT! constant random value!\r\n"
	many calls to 

### sub_5e35() -> rng_test_get()
IN: nil
OUT: rx24 = random byte?
Simulator Delay: about 1 second per invocation
	...
```c
	int accumulator=0;
	for(i=0; i<16; i++) {
		int coinflip = 0x1 & getRandomWord();
		accumulator |= coinflip << i;
		total_heads += coinflip;
	}
	if (i!=16) die();
	if (rng_test_count >= 12) {
		if (total_heads < rng_test_count*4) {
			print("You seem to be attempting to influence the RNG...");
			die()
		}
		if (total_heads > rng_test_count*12) {
			print("You seem to be attempting to influence the RNG...");
			die()
		}
	}
	if (rng_test_count == 101) {
		total_heads = 0;
		rng_test_count = 0;
	}
	0x2bcd[2*coinflip_vector_offset] ^= accumulator
	coinflip_vector_offset = (coinflip_vector_offset+1)/0x11
	return 0x2bcd[2*coinflip_vector_offset+1]
```

### sub_4709
Called from main, just after welcome message
	- does a bunch of memcpy type things
	- malloc to 2c11
		- 2c11: whole pile of nulls
		- free()d before end
	- sets word_102acf to something important
		- malloc()
		- 2d0e: 51 8e 1d f5 46 bf 63 a1 0c 03 a8 6b fd 95 8a a9
		- of length 0xfb=251

### raw data at word_102acf
```
data 0x2D00  00 00 00 00 00 00 00 00 00 00 00 00 fb 00 51 8e  ............û.QŽ
data 0x2D10  1d f5 46 bf 63 a1 0c 03 a8 6b fd 95 8a a9 10 eb  .õF¿c¡..¨ký.Š©.ë
data 0x2D20  6a 40 c5 f0 2f 80 77 84 c9 1c 55 6d b9 a6 be 67  j@Åð/€w.É.Um.¦.g
data 0x2D30  ca 4d c0 ad 3c f3 44 29 57 36 95 bf 82 e1 1d ed  ÊMÀ.<óD)W6.¿.á.í
data 0x2D40  f4 10 f1 4a c5 0e 01 32 a4 76 93 8b b3 0a 65 6f  ô.ñJÅ..2¤v“...eo
data 0x2D50  80 32 7f 69 7e 82 e5 b3 15 b7 45 7b 8e 39 c5 91  €2.i~.å..·E{Ž9Å‘
data 0x2D60  3c 55 aa 87 52 06 09 6f 15 e5 76 55 30 29 dd 44  <Uª.R..o.åvU0)ÝD
data 0x2D70  d1 ea ce 9b ea 2b 98 f4 4b 5e 0e 5b 2d 8a 55 08  ÑêÎ.ê+˜ôK^.[-ŠU.
data 0x2D80  c3 4e 77 db d9 26 38 04 48 2f 32 ec 94 35 fe 02  ÃNwÛÙ&8.H/2ì”5þ.
data 0x2D90  b5 e7 c9 ac a7 dd 87 4f 57 76 33 71 2d 44 15 98  µçÉ¬§Ý.OWv3q-D.˜
data 0x2DA0  33 75 0e cc fe 0e 45 7b f2 4c c3 d6 e6 55 97 6d  3u.Ìþ.E{òLÃÖæU—m
data 0x2DB0  41 58 e5 7f 76 3d e8 c7 c4 83 24 b5 af 4a 55 fc  AXå.v=èÇÄƒ$µ¯JUü
data 0x2DC0  e7 1a 4d 14 53 43 46 4d c2 6a 74 13 e2 91 2d 70  ç.M.SCFMÂjt.â‘-p
data 0x2DD0  5c e0 b4 19 b4 9d d0 16 54 fb ef 6a d2 d0 27 d9  \à´.´.Ð.TûïjÒÐ'Ù
data 0x2DE0  3b 4c ae 58 78 8c 78 de 68 d2 42 e8 90 d9 c9 d3  ;L®XxŒxÞhÒBè.ÙÉÓ
data 0x2DF0  13 af 24 d7 a6 bd 0a 1c ef 2e 5e 44 71 3c bb 53  .¯$×¦...ï.^Dq<»S
data 0x2E00  39 0c 68 d9 36 a0 cd 05 00 00 00 00 00 00 00 00  9.hÙ6 Í.........
```

###

## Dynamic
### Init
Note: can't just run simulator, is too slow.

Break:
	5d5a / 0xbac4: interesting function
	5d6a / 0xbad4: read_str_until
	65c0 / 0xcb80: usart_print
	6264 / 0xc4c8: just after readUserId

Patch:
	3018: 8f3f -> 8330
	bfb2: 8d83 -> 8f70 90e0 8b83 1c82 8d83 1e82
	likely need to at 5cff and 5d30 as well


