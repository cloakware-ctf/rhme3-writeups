
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
			// how do we get out of this???
			// -> we don't, we're locked once we get in.
		}
	} else if (strcmp(Y+20, "risc")) {
		X = 0x200a;
		Z = 0x225e;
		for (rx24 = 298 ; rx24>0; rx24--) {
			*X++ = *Z++
		}
		X = 0x2134;
		Z = 0x2388;
		for (rx24 = 298 ; rx24>0; rx24--) {
			*X++ = *Z++
		}
		do_test();
	} else {
		// do nothing
	}
```

## Reversing
### Variables:
    r17 = a byte
	rx16 = a word r16+r17
	erx = long
	rrx = long long

### branches:
	brcs <= true if abs(LHS) < abs(RHS)
	generally: cp x,y is like x-y.
	

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

### Math Functions
	floatsisf: erx22 = (float)erx22
	fixunssfsi: erx22 = (uint32_t)erx22
	round float to long
	mulsf3: erx22 *= erx18
	divsf3: erx22 /= erx18

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

#### raw data at word_102acf
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

### do_test_5b30()
Summary: inits 0x2a6b[0...100]
```c
do_test_5b30() {
	sub_55c4a()
	Y[1] = (get_RTC_CNT_644d() >> 8) & 0xff
	Y[6:7] = 100
	word_1029b1 = get_rand_word() % 100
	for (i=0; i<100; i++) {
		while (Y[1] == (get_RTC_CNT_644d() >> 8) & 0xff)
			;
		Y[1] = (get_RTC_CNT_644d() >> 8) & 0xff
		Y[4:5] = sub_5a20(i); // also references word_1029b1
		write_DACB_CHDATA(Y[4:5], 0x0000);
	}
	printf("test done")
}
```

### sub_5a20
IN: rx24=external loop iterator, 0..99
OUT: ???

```c
short sub_5a20(short i) {
         1:2   3:6    7:8  9:10
	Y = [ret, dword, word, arg0]
	// there's an even/odd split, similar, but...
	r24 = *(0x200a+i/2) or *(0x2134+i/2)
	ret = (int)(rx24*2730.0/100.0) // example: 28 -> 764;
	ret += 0x2aa
	if (i<50) return ret;
	if (i%5 != 0) return ret;
	if (i>=0x223) return ret; // how?
	rx24 = 0x81 & 0x2a6b[word_1029b1]
	if (r24 & 0x80) r24 = 0 - (r24&1) // possible: -1, 0, 0, 1
	word = 0x2aa * r24
	if (0x2a6b[word_1029b1] % 2) {
		ret -= 0x2aa
	} else {
		ret += 0x2aa
	}
	erx22 = ((0x2a6b[word_1029b1] + 1)/4 ) * 0x147b
	rx18 = (erx22>>17)*100
	0x2a6b[word_1029b1] += 1 - rx18
	return ret;
}
```

### sub_7049 -- write_DACB_CHDATA
```c
void write_DACB_CHDATA(short low, short high) {
	DACB_CH0DATA = low
	DACB_CH1DATA = high
}
```

### get_RTC_CNT_644d MACRO
IN: nil
Out: r24
```fasm
0x940E 644D call    get_RTC_CNT_644d ; get tick count?
0x9592      swap    r25
0x9582      swap    r24
0x708F      andi    r24, 0xF
0x2789      eor     r24, r25
0x709F      andi    r25, 0xF
0x2789      eor     r24, r25
```
Examples: 17c -> 17
 abcd
 badc
 ba.c
 bab[ca]
 .ab[ca]
 .abc


### sub_55c4
```c
void sub_55c4() {
	char *array = 0x2a6b;
	const char subVector[] = {...};
	const char xorVector[] = {...};
	memset(array, 0x05, 100); // really, store "5"
	for(i=100; i>=0; i--) {
		array[i] -= subVector[i];
	}
	for(i=100; i>=0; i--) {
		array[i] ^= xorVector[i];
	}
	sub_4ffb();
}
```

#### Result byte_102a6b
data 0x2A60  .. .. .. .. .. .. .. .. .. .. .. 8d 88 14 e0 28  ............ˆ.à(
data 0x2A70  56 f7 5d 51 e4 f1 5d a8 7c a4 00 92 78 1b 17 44  V÷]Qäñ]¨|¤.’x..D
data 0x2A80  c6 28 55 d9 3a 31 aa ad 30 33 7d f9 39 f3 67 af  Æ(UÙ:1ª.03}ù9óg¯
data 0x2A90  ef d0 fe 73 09 64 a8 8d 88 c1 8c 24 19 4b 9c f1  ïÐþs.d¨.ˆÁŒ$.Kœñ
data 0x2AA0  84 cd e8 7f 15 04 62 7f bb 1e 2a ad 7b 35 62 b0  .Íè...b.».*.{5b°
data 0x2AB0  e9 d9 da 12 0d 90 3c c9 c2 6f ab ad bb 6e d3 f5  éÙÚ...<ÉÂo«.»nÓõ
data 0x2AC0  0c 02 99 1c 25 ca 1d 24 5c b0 2c d9 53 b3 88 ..  ..™.%Ê.$\°,ÙS.ˆ.

### sub_4ffb
IN: nil
OUT: nil
```c
void sub_4ffb() {
	char array[]; // stack allocation at 0x3f44
	for(i=0; i<100; i++) {
		array[i] =  byte_102a6b[i];
	}
	/* next: 100 times:
	 * byte_102a6b[i] ^= array[f(i)]
	 */
	/* next: 100 times:
	 * byte_102a6b[i] ^= byte_102a6b[f(i)]
	 */
}
```

#### result byte_102a6b
data 0x2A60  .. .. .. .. .. .. .. .. .. .. .. 79 40 c8 bf 07  ...........y@È¿.
data 0x2A70  e4 5d e1 6b 03 14 ba 1e 26 f8 3a 2c ea 65 0d 6d  ä]ák..º.&ø:,êe.m
data 0x2A80  0a 27 fd c9 d9 3a f4 c7 44 a5 4f 34 8c e3 a6 8e  .'ýÉÙ:ôÇD¥O4Œã¦Ž
data 0x2A90  cb 6b 7d e1 a4 5d 7e 42 85 4e 93 0d 6a 43 d0 c0  Ëk}á¤]~B.N“.jCÐÀ
data 0x2AA0  03 aa 97 f8 8f fa e9 83 28 7e 58 64 96 7b 12 9c  .ª—ø.úéƒ(~Xd–{.œ
data 0x2AB0  6b 75 e0 63 f1 a6 b0 26 1b 36 f8 9f c1 d4 cc f7  kuàcñ¦°&.6øŸÁÔÌ÷
data 0x2AC0  f3 50 aa 83 aa b0 aa 0b 24 f6 20 b5 23 f0 a3 ..  óPªƒª°ª.$ö µ#ð£.



## Backtracking from Flag:
### process_star_4f57(byte)
IN: r24 = a byte
OUT: nil
Summary:
	* Uses the time since last byte as input
```c
         1:2   3:4    5
	Y = [ret, kTick, byte]
	if (byte == '*') {
		you_entered_4e70();
		return;
	} else {
		kTick = get_RTC_CNT_644d() >> 11; // I get zero, maybe sim issue?
		bit1 = (kTick < last_kTick) ? 1 : 0; // part 1 - time rewound?
		bit2 = (kTick+0x1f < last_kTick+4) ? 1 : 0; // part 2 - time wrap?
		if (bit1==0 || bit2==0) {
			if (last_kTick >= kTick) {
				ret = kTick - last_kTick;
			} else {
				ret = kTick + 0x1f - last_kTick;
			}
		} else {
			password_len_102009 = 254; // aka death
			ret = 0;
		}
		if (ret >= 2) {
			password_len_102009 += 1
		}
		last_kTick = kTick
		if (password_len_102009 < 250) {
			password_102ad3[password_len_102009] += 1
		}
		return;
	}
```

### you_entered_4e70()
IN: nil
OUT: noreturn
Note: I've commented out lots of the flak to make it easier to read
Summary:
	- print the "entered string", in password_102ad3
	- expect exactly 250 characters??
	- if (password_len_102009 < 240) die();
	  else password_len_102009 = 254
	- x = process_password_47cc();
	- password_or_die_4dBF(x, '+');
	- die()
```c
void you_entered_4e70() {
	printf "You entered the following string: "
		iter = 0;    // Y+1
		limit = 250; // Y+2
		c3 = 0xc3;   // Y+3 -- actual assignment later
		p_c3 = &c3;  // Y[4:5]
		while (iter ~ password_len_102009 && iter ~ 250) {
			//if (limit ~ 0) die();
			//test_const_rng_17f1();
			limit -= 1;
			//test_const_rng_17f1();
			//if (iter ~ password_len_102009 && iter ~ 250) die();
			if (iter+1 % 20 == 0) printf("\r\n");
			printf("%02hhx", password_102ad3[iter]);
			iter += 1;
		}
	printf("\r\n");
	if (iter ~ password_len_102009 && iter ~ 250) die();
	//test_const_rng_17f1();
	if (password_len_102009 < 240) die();
	password_len_102009 = 254;
	c3 = 0xc3; // or 0xc3 or 195, hard to be sure
	p_c3 = &c3;
	//test_const_rng_17f1()
	Y+6 = process_password_47cc(p_c3);
	/* more bs busywork */ {
		//test_const_rng_17f1()
		if (Y+6 ~ 'i') die();      // 0x69 / 105
		if (*(p_c3) ~ '<')  die(); // 0x3c
		if (Y+6 !!~ 'i') die();
		if (*(p_c3) !!~ '<')  die();
		if (Y+6 ~ 'i') die();
		test_const_rng_17f1()
		Y+7 = 0x3c^0xc3;
		test_const_rng_17f1()
		if (Y+7 != 0xff) die();
		test_const_rng_17f1()
		if (*(p_c3) !!~ '<')  die();
		if (Y+6 ~ 'i') die();
		if (*(p_c3) !!~ '<')  die();
		if (Y+7 != 0xff) die();
	}
	password_or_die_4dBF(Y+6, p_c3)
	die();
}
```

### process_password_47cc()
IN: rx24=0x3f25; // stack offset, pointing to 0xc3
OUT: rx24=0x69; // or 0x96, but only if we fail
Summary:
	* crazy mess
	* on the return path, does a bitwise not on *arg0
```c
	Y+1 = 0;
	Y+2 = 0x65
	Y+3 = 0xCD
	Y+4 = 0x1D
	Y+5 = 0;
	Y+6 = 0;
	Y+7 = 0;
	Y+8 = 0;
	rYx9 = 0x0FA93ABC; // Y+9..Y+0x10
	Y+0x11 = 0;
	Y+0x12 = 0;
	Y+0x13 = 0;
	Y+0x14 = 0;
	Y+0x15 = 0;
	Y+0x16 = 0;
	Y+0x17 = 0;
	Y+0x18 = 0;
	Y+0x19 = 0;
	Y+0x1a = 0;
	ret = 0x96; // Y+0x1b
	ramp = CPU_RAMPX; // Y+0x1c, Y+0x1d
	arg = ?; // Y+0x20, 0x21
	printf("Processing password...")
	printf("0% complete...")
	rYx9 += 0xF252B44; // 0x1ece_7700
```


### password_or_die_4dbf()
IN: r24=='i', rx22==&'3c'
OUT: nil
```c
	Y+12 = init_word_2acf_4709()
	tmp = 5;     // Y+3 -- testing for FI
	arg0 = r24;  // Y+4
	arg1 = rx22; // Y[4:5]
	if (check_code_160(password_102ad3, Y+12)) {
		printf("Wrong Code");
		die();
	}
    // bunch of bs, call check_code_160() three more times, same args
	const_0xb3 = 179; // for later tests
	flag_4d15(arg0, arg1);
	return;
```

### check_code_160()
aka sub_164()
IN: rx24=processed pasword
IN: rx22=init_word_2acf_4709()
OUT: rx24=boolean, false if wrong code.
```c
	acc = 0;          // Y+1, Y+2
	processed = rx24; // Y+3, Y+6
	correct = rx22;   // Y+5, Y+6
	for(int i=0; i<250; i++) { // unrolled
		acc |= processed[i] ^ correct[i];
	}
	return acc;
```

### flag_4d15()
IN: r24=='i', rx22==&'3c'
OUT: nil
Summary: if we get here legit, we win.
```c
	b3 = 0xb3;   // Y+1
	tmp = 1+4+7+12+0x26;     // Y+2
	arg0 = r24;  // Y+3, constant: 0x69, 'i'
	arg1 = rx22; // Y+4,Y+5, is a pointer to value: 0x3c, '<'
	printf("Secret management interface accessed!");
	printf("Your flag is: ");
	// bunch of tests, input parameters, and precalls
	// must have called sub_1a30()
	// which says things about init_word_2acf_4709()
	print_flag_73c3(0x65ac);
	return;
```

## Dynamic
### Init
Note: can't just run simulator, is too slow.
Note: with patches below, takes ~5-10 minutes

Break:
	5d5a / 0xbac4: interesting function
	5d6a / 0xbad4: read_str_until
		- skip it, and populate 0x3fde
		- rx22 <= buffer
	65c0 / 0xcb80: usart_print
		- string is in rx22
		- 28b2=='starting...'
		- 28c2=='welcome to the maintenance interface...'
	6264 / 0xc4c8: just after readUserId
		- writes to 0x3f96, put something else there

Patch:
	3018: 8f3f -> 8330
	bfb2: 8d83 -> 8f70 90e0 8b83 1c82 8d83 1e82
	b9fe: 3a41 -> 3105 4105
	ba60: 3a41 -> 3105 4105
	b94c: 8ae1 -> 80e0 .... 80e0

Star:
	*0x3fde = 2a 0a 00
	break 0x5d94, and r24=(byte)


### Watches
r16+256*r17
r18+256*r19
r20+256*r21
r22+256*r23
r24+256*r25
r26+256*r27
r28+256*r29
r30+256*r31

## Sigint
	* Attaching the logic analyser to A[0..5] didn't pick up anything.
	* Reading RX and TX got the obvious comms
	* on D7 see a clear signal

### D7
Signal detected between "test\n" and "Test done\n"
Difference signal detected between "risc\n" and "Test done\n"

However, what they mean is non-obvious, more reversing time...


## Write Up
The code is obviously loaded with FI detection and RNG pinning detection. More than that, it regularly detects if the RNG is meaningfully biased. There's a lot of busy work and a lot of delay in that.

Looking at main(), it responds to three inputs 'test', 'risc', and '*'. We need to know what those do. Since I wanted to go dynamic, but the busywork slowed the simulator down too much (it would take hours, at least, to get to the meat of the code), I devise a set of patches to bypass some of the busy work. I didn't know whether things were safe to skip completely, so I generally just shaved off the high bytes, so that we'd do a couple hundred tests instead of tens of thousands. That done, it was on to reversing the 'test' path...

After doing a bunch of dynamic work, I realized how much code there is between me and the flag. I need to reverse smarter: back-track from the flag.

main_5c13()
	-> process_star_4f57()
		-> you_entered_4e70()
			-> process_password_47cc()
			-> password_or_die_4dbf()
				-> init_word_2acf_4709()
				-> check_code_160()
				-> flag_4d15()
					-> print_flag_73c3()
	<- infinite loop, process_star()

What we see here, is that once we enter process_star(), we're not getting out. What needs to be true?

It looks like:
	* 0x2009 = "entered string" length, which must be 250
	* 0x2ad3 = "entered string"

Aside: what does "risc" do?
	* memcpy(0x200a <- 0x225e, 596 bytes);
	* I have no idea what that could mean, I have no xrefs in that region
	* I don't see any point to it.
	* Possible it reveals the key somehow

I've finished understanding how process_star_4f57() works. Description follows:
	* we're using a serial character device like a analog input.
	* It will "pulse count", need to be faster than ~0.8ms 
	* Basic idea: if I want to send 0x11223344, then
		- send "*\n"
		- pulse 0x11 times, fast; then wait: 1ms<wait<3ms
		- pulse 0x22 times, fast; then wait: 1ms<wait<3ms
		- ...
		- send '*'

Next Steps:
	* apply logic analyzer, both in 'test', and 'risc'.
	* actually deliver any payload to it, just to prove I can.

Open Questions:
	* what is the point of 'risc'?

I built a payload and sent a long test string. A wait value of 4 seconds seems about right, but didn't work in practice. I suspect I'm waiting too long and occasionally failing the wrapping test. Time to read the docs...
	* reading from RTC_CNT
	* have set RTC_PER=0xFFFF
	* ... wait, do_test_5b30() also reads from the RTC...
    * The logic analyzer only reads digital, but using the scope, I found that it's operating at a resolution of 40-45us.
	* Now, that should correspond to 256 clock ticks
	* Also, we loop 100 times in 4ms, so each loop should take 40us
	* that's 6.4 MHz.
	* from above, 256 tick -> 40us, so 2048 ticks -> 320us.
	* so if we're within 1.28ms, that's a pulse, and within 10.24 is a space
	* that means I need millisecond resolution. Time for C?

More work... looks like I had it right the first time. However, once the numbers get big enough, it buffers up. This means:
	1. sometimes the sleep isn't as long as I think, because we start sleeping before the board is done processing its backlog
	2. sometimes I can ram characters down its throat so fast it drops some.
	3. Fixing with a 10ms sleep per charcter, and a tcdrain(fd).

