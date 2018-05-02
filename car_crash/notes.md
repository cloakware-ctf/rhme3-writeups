
## Car Crash
This ECU firmware dump, or what's left of it, was taken out of a crashed prototype car. We have to extract the logs from it to investigate the crash. Bad luck, we get some strange garbage printed instead.

Attached is a program you can reverse-engineer and a program you can test. Don't mix them up.

## General Reversing
### Prologues and Epilogues
Prologue:
	- push anything outsize of r18..r31
	- push Yx
	- sbiw Y, <stack frame size>
		* note, above is a positive number, `sbiw Y, 4` allocs 4 bytes
		* which would mean Y+1 .. Y+4 are available

## Overview
	* We start out with 240 known bytes in Y+6
		* comes from known_102308
		* (we know it because we can print it using command 2)
	* We can "decrypt" once, which takes the address of Y+6 and populates that
		* we call it with buffer and length=256, which overflows by 16... but that just wrecks the return of main, which doesn't.
		* uses key_102268
		* decrypts in place, on buffer at 0x3faa
	* Our unencrypted firmware prints the same ciphertext and 'plaintext' as the encrypted one, which almost certainly means the key is the same.
	* There is 256 bytes of unused data at RAM:0x2010
		* it's the inverse sbox! (actually, I probably have them backward, this is probably forward...)
	* Ok, so what if I flip the crypto?
		* sbox is used in `block_decrypt_702()`
		* inverse_sbox_102010 is used in `block_encrypt_568()`
		* later is uncalled, so need to change the call at `93c / 1278` to point to `0568`... no dice.

## .data
Common:
	* 0x8a0 -- USART
	* 0x640
	* 0x804
	* 0x2000 -- *USART
	* 0x9b0
	* 0x660
	* 0x8040
	* 0x2008 -- *0x9b0
Unusual:
	inverse_sbox_102010 -- 256 bytes of inverse sbox
	sbox_102110 -- 256 bytes of sbox
	unknown_102210 -- 16 bytes of ???, used in a bunch of crypt ops
	bunch of  strings
	key_102268 -- 32 bytes of key
	some more strings
	known_102308 -- 240 bytes of ciphertext

## Reversing
```c
int main_9a5() {
	short decoded = 0;  // Y+1,2
	short length = 256; // Y+3,4
	char  choice = ?;   // Y+5
	char  known[241];   // Y+6..0xF6 -- 240 bytes, plus null terminator

	init_clock();
	some_init_a6b(); // more init
	for (int i=0; i<241; i++) {
		known[i] = known_102308[i];
	}
	// init of decoded and length happen here
	serial_printf("Black box connected\n");

	while (true) {
		choice = menu_89d();
		serial_printf("Option: %d", choice);
		switch(choice) {
			case 1: // decrypt data
				if (decoded) {
					serial_printf("Already decoded!\n");
				} else {
					decrypt_data_8f1(known, length);
				}
				decoded = 1;
				break;
			case 2: // print data
				//print_data_955(known);
				printf("%s", known);
				break;
			case 3: // status
				serial_printf("Car not found\n");
				serial_printf("Have you tried turning it on and off again?\n");
				break;
			default:
				serial_printf("Wrong input");
				break
		}
	}
}

char menu_89d() {
	char* buffer[3]; //Y+1
	serial_printf("1. Decrypt EDR data\n");
	serial_printf("2. Print EDR data\n");
	serial_printf("3. ECU status\n");
	len = read_str_until(0x2000, buffer, 3, '\n');
	return atoi_bc7(buffer);
}

char atoi_bc7(char* buffer) {
	char c;
	SREG[T] = false;

	do {
		c = *buffer++;
		if (c==' ') continue;
		if (9<c && c<0xe) continue; // 0xd and 0xa ?
		break;
	}
	if (c=='+') {
		c=*buffer++;
	} else if (c=='-') {
		SREG[T] = true;
		c=*buffer++;
	}
	do {
		x = c - '0';
		if (x < 10) {
			acc = 10*acc + x;
		} else {
			break;
		}
	}

	if (SREG[T]) acc = -acc;
	return acc;
}

unsigned char key_102268[32] = {
	44 11 bb ce f0 aa 4a b4  fa 1a d1 0a e0 9b bd 3d
	88 e3 36 d9 47 16 ea d7  5c 00 41 cf a1 f7 d9 80
};
unsigned char schedule[160] = {
	44 11 bb ce f0 aa 4a b4  fa 1a d1 0a e0 9b bd 3d, // key line 1
	88 e3 36 d9 47 16 ea d7  5c 00 41 cf a1 f7 d9 80, // key line 2
	4a d4 07 ae a8 1c 24 62  3d 3f 55 02 2b 7a cd 5a,
	81 f7 55 75 3f 02 23 1d  3f 02 5f 96 c6 f4 e1 54,
	a1 d4 e1 e4 04 bd 9c 54  95 d6 89 d9 34 d4 b9 c8,
	ce 5d 04 9b 3e 51 33 86  95 76 bb a5 12 4b cb 33,
	81 55 4f 47 30 d5 85 a7  af 54 8a 00 31 b0 40 82,
	4e 76 7c 7c 5f 23 70 0e  82 83 29 ad e1 60 77 49,
	25 4c a3 69 fd 80 b2 4b  a7 1a 22 01 ef 63 f9 4a,
	43 43 4c f9 74 4d 81 78  31 cc 92 69 02 8a 5c 1c,
};
void decrypt_data_8f1(char buffer[241], short length) {
	// alloc 0xc6 on stack
	short i;            // Y+1
	char schedule[160]; // Y+3      -- 0x3d3c
	char array[32];     // Y[0xa3]  --
	char** buffer;      // Y[0xc3]  -- 0x3e0a
	short* length;       // Y[0xc5]

	for (i=0; i<32; i++) {
		array[i] = key_102268[i];
	}
	key_schedule_207(schedule, array); // key scheduling
	serial_printf("Decrypting data\n");

	for (i=0; i<length; i+=16) {
		block_decrypt_702(schedule, buffer+i); // block encryption -- 16 bytes
	}
}

void key_schedule_207(char schedule[160], char key[32]) {
	short i = 0;           // Y+3
	short unk1 = schedule; // Y+6
	for (i=0; i<16; i++) {
		// TODO -- decompile
	}
	// TODO -- decompile
	calls sub_155()
	calls sub_155()
}

void block_decrypt_702(char schedule[160], char buffer[16]) {
	// stack frame: 0x30 -- 48 bytes -- 6 qwords
	short i;            // Y+0x01 .. Y+0x02
	short r;            // Y+0x03 .. Y+0x04
	char state[16];     // Y+0x05 .. Y+0x14
	char** schedule;    // Y+0x15 .. Y+0x16 -- 0x3e3c
	char** buffer;      // Y+0x17 .. Y+0x18 -- 0x3faa
	char unused1[8];    // Y+0x19 .. Y+0x20 -- temp swap
	char unused2[16];   // Y+0x21 .. Y+0x30 -- temp swap

	for (i=0; i<16; i++) {
		state[i] = buffer[i] ^ schedule[0x90+i]
	}

	for (short i = 8; i>=0; i--) {
		sub_1af(state);
		for (r=0; r<16; r++) {
			state[r] = sbox_102110[state[r]];
		}
		for (j = 0; j<16; j++) {
			state[j] = state[j] ^ schedule[i*16 + j]
		}
	}
	for (i=0; i<16; i++) buffer[i] = state[i];
	return;
}

void block_encrypt_568(char schedule[160], char buffer[16]) {
	// very much like decrypt
	// calls sub_155 instead of sub_1af
}

void sub_1af(char state[16]) {
	short j;          // Y+1..2
	short i;          // Y+3..4
	char  c;          // Y+5
	char** state;     // Y+6..7
	calls sub_126() -> sub_129()
	for (i = 0; i<16; i++) {
		c = state[0]
		for (j = 0; j<16; j++) {
			state[j] = state[j+1]
			r25 = sub_126(state[j], byte_102210[j]);
			c ^= r25
		}
		state[15] = c;
	}
	return;
}

?? sub_155(...) {
	// XXX close match to sub_1af
	calls sub_126() -> sub_129()
}

char sub_129(char a, char b) {
	char acc; // Y+1
	char a;   // Y+2
	char b;   // Y+3
	for (b; b!=0; b>>=1) {
		if (b&1) acc ^= a;
		a = (a>>1) ^ (a>=0 ? 0 : 0xc3);
	}
	return acc;
}
```

## Dynamic
Break:
	09a5 / 0x134a -- main()
		* move SP to 16127
	0b34 / 0x1668 -- printf()
	09d8 / 0x13b0 -- j_menu() callsite
		-> set r24: 1:decrypt, 2:print
	093c / 0x1278 -- decrypt_data_8f1 callsite, either 568() / 702()
	` to point to `0568`... no dice.


On main_9a5()
	Y is 0x3f04
	known is at 0x3f0a

On read_str():
	- buffer is 0x3efd
	- buflen is 3
	- all checks out, no overflow

Print Data:
	- prints from 0x3efc:
		0a 6d 0a 6d 6d 04 00 0a 2c 00 00 00 01 00 60 ed
		82 39 43 0c d9 c9 46 20 13 ab 10 e4 52 2d 30 06

Plan:
	* I'm at the entry point to the 11th call to block_decrypt_702()
	* this is the loop that bails early and doesn't decrypt the flag
	* rx24 = 0x3e3c = schedule
	* rx22 = 0x3faa = cipher-block

## Data
Simluator -- Pre-decrypt:
	                              60 ed 82 39 43 0c
	d9 c9 46 20 13 ab 10 e4 52 2d 30 06 2f c4 c0 45
	c7 3a e9 4e 8f 2a 89 5c c8 64 2a f5 99 04 6b 94
	d5 e0 d9 75 ce d1 d8 83 8d 93 e3 84 47 85 8e 69
	6c bb 3a a1 e9 dd ff 44 c2 d1 60 ed 82 39 43 0c
	d9 c9 46 20 13 ab 10 e4 52 2d 96 25 70 ea 4c 6f
	64 6a f9 69 d3 a5 25 94 2f 01 6a e7 29 3f 61 a1
	d5 cf 26 d5 bd 87 42 67 48 ff 60 ed 82 39 43 0c
	d9 c9 46 20 13 ab 10 e4 52 2d aa 30 47 ef 1f 72
	75 13 55 56 c3 6b 4c 43 ec 43 7e 80 a1 c9 bc 57
	87 ab b8 fd 6b 9a 4b e5 22 ca 8a 13 f3 9c 6c 37
	3a 57 b4 20 f3 5a 29 0b 3a 45 46 f8 21 89 a5 3f
	a7 9b 62 64 10 30 a8 68 09 31 69 39 2d 58 78 2d
	9f e0 8b 22 24 6a c5 f8 b7 bf b5 90 36 92 19 7e
	dc 54 53 37 31 da a2 58 3c d4 4f aa 1a 02 06 2b
	23 28 34 99 1d a5 3c 78 9a 07

Actual Board -- Pre-decrypt:
	               60 ed 82  39 43 0c d9 c9 46 20 13
	ab 10 e4 52 2d 30 06 2f  c4 c0 45 c7 3a e9 4e 8f
	2a 89 5c c8 64 2a f5 99  04 6b 94 d5 e0 d9 75 ce
	d1 d8 83 8d 93 e3 84 47  85 8e 69 6c bb 3a a1 e9
	dd ff 44 c2 d1 60 ed 82  39 43 0c d9 c9 46 20 13
	ab 10 e4 52 2d 96 25 70  ea 4c 6f 64 6a f9 69 d3
	a5 25 94 2f 01 6a e7 29  3f 61 a1 d5 cf 26 d5 bd
	87 42 67 48 ff 60 ed 82  39 43 0c d9 c9 46 20 13
	ab 10 e4 52 2d aa 30 47  ef 1f 72 75 13 55 56 c3
	6b 4c 43 ec 43 7e 80 a1  c9 bc 57 87 ab b8 fd 6b
	9a 4b e5 22 ca 8a 13 f3  9c 6c 37 3a 57 b4 20 f3
	5a 29 0b 3a 45 46 f8 21  89 a5 3f a7 9b 62 64 10
	30 a8 68 09 31 69 39 2d  58 78 2d 9f e0 8b 22 24
	6a c5 f8 b7 bf b5 90 36  92 19 7e dc 54 53 37 31
	da a2 58 3c d4 4f aa 1a  02 06 2b 23 28 34 99 1d
	a5 3c 78 9a 07

Actual Board -- Post-decrypt:
							 46 e0 5f 62 98 08 29 b4
	6e 97 4e f5 78 65 87 ec  52 2f 39 08 5a c5 db a7
	22 72 b5 f3 e0 db 52 fc  c4 86 f0 83 25 a3 6d 69
	f6 8a fa 14 aa 85 80 c1  9b d7 e3 c8 2c 82 6c 93
	21 22 60 27 91 e7 1a df  46 e0 5f 62 98 08 29 b4
	6e 97 4e f5 78 65 87 ec  92 48 bb 28 4b 5e 2d e1
	28 e8 b0 2f 20 6b c0 1b  e2 39 38 ce 36 aa 52 c1
	56 24 09 2c 24 0c 77 e1  46 e0 5f 62 98 08 29 b4
	6e 97 4e f5 78 65 87 ec  86 6f ba a9 71 5f 4e f9
	ea 34 06 ad 06 3c ef 05  70 ed 3f 46 31 b5 e1 3a
	5e 8a 13 e7 6c a9 05 c6  ba 7c 20 f1 68
(likely premature null-termination due to bad decrypt)

## Plan
	1. Take the decompilation above, make it actually compile
	2. Compare it's actions with those of the simulator to debug
	3. Fix the C.

