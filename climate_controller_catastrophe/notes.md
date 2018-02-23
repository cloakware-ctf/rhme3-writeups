
## Challenge
Catting cars is a major issue these days. It's impossible to sell your stolen car as a whole, so you sell it in parts. Dashboard computers are popular since they break quite often ;-).

Unfortunately, the dashboard computer is paired with the main computer. So, simply exchanging it will not do the trick. In fact, without the handshake to the main computer it will not operate the climate control buttons.

Of course just pairing the dashboard computer isn't cool enough, try to smash the stack instead! We suspect the device isn't using the serial interface for its pairing algorithm.

In addition to the attached challenge and reversing binaries, you're provided a special "challenge" which you can flash to wipe the EEPROM of your dashboard computer.

## Initial Analysis
X <- Z // data
	Z = 0x12612
	X = 0x2000 .. 0x25bc
X <- 0 // bss
	0x25bc .. 0x3081

avr_loader_emu(0x12612, 0x2000, 0x25bc)
avr_bss_emu(0x25bc, 0x3081)

## Serial Chatter
```
Initializing...
Initialization complete
```

Scoping out the leads, we see traffic on:
	- D7
	- D9, D10, D11, D13

Oscilloscope, check for analogue signals:
	- D6, D9, D10, D11, D13
	- D12: suspicious spike/trailoff

Transcription:
	T0. D6 goes low, D11 blips low for .583 us
	T1. D13 pulses high 4 times 83ns, D11 spends most of that low, D10 blips low, later D6 goes high.
	T2.0. D6 goes low for duration, D11 goes low three times, each time D13 goes high 5,5,4 times.
	(tiny delay)
	T2.1. similar to T2, but D10 blips low, and D11 is less stable in first pulse
	T2.2. D10 pulses low, D9 drops low
	T3. D6 goes low for duration, D11 goes low once, in which time D13 goes high 4 times.
	T4. actual meaningful conversation, on lines D6, D9, D10, D11, D13

Legend:
	D6 -> c1
	D7 -> c2 unused
	D8 -> c0 unused
	D9 -> c3
	D10 -> c4
	D11 -> c5
	D12 -> c7
	D13 -> c6

Spec sheet says that D6,11,12,13 are SPID. I analysed as SPI, and got something.
Consulted with Ben: he noticed that D9,10 are two lines of a SPI as well. Checking out the board schematics, he noticed that those lines are also the inputs to the CAN controllers.

Current Theory: The CANBUS is active and listening for packets. We need to connect to it and start sending frames. Good frames will likely get us responses over the serial line.

### Pin Outs
	D7,8 -> pin 6,7 -> PB2,3
		- unused
	RX,TX -> pin 12,13 -> PC2,3
	D9,10 -> pin 14,15 -> PC4,5
		- Port C
		- RX/TX can be used as USART C0
		- D9,10 can be used as TCC1/OC1A,B
	D6 -> pin 24 -> PD4
	D11,12,13 -> pin 25,26,27 -> PD5,6,7
		- Port D
		- D6,11 can be used as TCD1/OC1A,B
		- D12,13 can be used as USB D-,D+, USART D1
		- SPI: D6; D11,D12,D13

Notes:
	USARTC0 is at 0x8a0 .. 0x8a7
	USARTC1 is at 0x8b0 .. 0x8b7
	USARTD0 is at 0x9a0 .. 0x9a7
	USARTD1 is at 0x9b0 .. 0x9b7

Notes:
	USARTD1_DATA is referenced at 2121, which is referenced at 2127

### Reversing: Looking for I/O:
	* DACB_CTRLA -- lots of code, but at the end, uncalled
	* ADCA_CTRLA -- also referenced, but uncalled

I suspect that the secondary I/O happens over USART D1, using interrupts. Which means `eicall`.

Syntax:
	PC <= EIND:ZH:ZL

generate_session_key_2b8a
	sub_521D
		4x eicall
	...
	sub_532B
		LOTSx eicall
	sub_5599
		LOTSx eicall

print_flag_8bb8
	eicall usartC0_send_byte
fputc
	eicall

## Decompilation
```c
Note: ROM:0x3bf is left on stack
void init_flag_array_89bb(void) {
	// stack frame: 11
	char i;              // Y+1
	void* off=ROM:0x3bf; // Y+2..3
	uint32_t y4;         // Y+4..7
	uint32_t y8;         // Y+8..11

	y4 = *(uint32_t*)off; // zero in my build
	y8 = r4;
	sub_8922(0x2ef1, y8);
	y8 = 0;
	for (i=0; i<8; i++) {
		flag_array_102f01[i] = sub_885c(0x2ef1);
	}
}

IN: r24 = 0xF0
OUT: rt24 == 0x0F || die()
char test_eeprom_4f91(char arg0) {
	// stack frame: 17
	char x = arg0; // Y+1
	char buf1[8];  // Y+2
	char buf2[8];  // Y+10

	memset(buf1, 0, 8);
	eeprom_read_block(buf1, 0x1001, 8); // EEPROM address 1
	memcpy(buf2, abba_10237A, 8);

	if (0 != strncmp(buf1, buf2, 8)) {
		x = load_default_cert_4eea();
	}

	eeprom_read_block(buf1, 0x1001, 8); // EEPROM address 1
	if (0 == strncmp(buf1, buf2, 8)) {
		x = 0xf;
	} else {
		x = cert_init_load_eeprom_4eea();
		// gonna die()
	}

	eeprom_read_block(buf1, 0x1001, 8); // EEPROM address 1
	if (0 != strncmp(buf1, buf2, 8)) remember_and_die();
	if (0 != strncmp(buf1, buf2, 8)) remember_and_die();

	return x;
}

char load_default_cert_4eea(void) {
	// stack frame: 0xab
	char check = 0;    // Y+1 -- or die() tests
	char offset = 0;   // Y+2 -- or die() tests
	char ret = 0xf0;   // Y+3
	char buf1[8];      // Y+0x4..0xb
	char buf2[24];     // Y+0xc..0x23
	char buf3[16];     // Y+0x24..0x33
	char buf4[120];    // Y+0x34..0xab

	// check ^= 1;
	memcpy(buf1, abba_10237A, 8);
	eeprom_write_block(buf1, 0x1001, 8);

	memcpy(buf2, array_102382, 24);
	eeprom_write_block(buf2, 0x100a, 24);

	memcpy(buf3, array_10239a, 24);
	eeprom_write_block(buf3, 0x1028, 16);

	memcpy(buf4, array_1022db, 120);
	eeprom_write_block(buf4, 0x1040, 120);

	ret = 0xf;
	return ret;
}
```

```c
/*** MAIN LOOP *******************************************************/

void main_loop_2c8b(void) {
	// stack frame: 0x22 -> 34
	uint32_t y1;    // Y+1..4
	short y5;       // Y+5..6
	short unused7;  // Y+7..8
	short y9;       // Y+9..10
	short yB;       // Y+11..12
	char yD[11];    // Y+13..23
	                // Y.....34
	y1 = 0;
	while (true) {
		if (byte_1021b9 != byte_1021ba) { // note 0x2137+0x82
			byte_1021ba = (byte_1021ba+1)%8;
			rx24 = byte_1021ba * 14 + 0x12;
			frame_read_25a0(&yD, &body_structs[byte_1021ba]); // index is rx24 above
			frame_enqueue_2612(yD);
		}
		if (is_whole_msg_waiting_26e3()) {
			// this block is doing dynamic stack allocation
			rx16 = $sp;
			y5 = msg_total_length_2654();
			unused7 = y5-1;
			$sp -= y5;
			y9 = $sp + 1;
			memset(y9, 0x0, y5);

			yB = sub_2720(y9);
			if (yB == 0x665) {
				eeprom_process_msg_1094(y9, y5);
			} else if (yB == 0x776) {
				cert_process_msg_66c8(y9, r5);
			} else {
				// nil
			}
			$sp = rx16; // stack back
		}

		y1 = (y1 + 1) & 0x1FFFF;
		if (y1 != 0x10000 && byte_102e5d) {
			try_readMessageBuffer_2575(); // XXX WTF?
		}
	}
	// forever
}

void frame_read_25a0(char frame[11], char* arg1) {
	// stack frame 0x11 -- 17
	short y1; //         Y+1..2
	canframe buf[11]; // Y+0x3..0xd
	// frame is at       Y+0xe..0xf
	// arg1 is at        Y+0x10..0x11
	y1 = arg1[5] * 41 / 56;
	if (y1 < 9) {
		memcpy(buf, &arg1[6], y1)
		buf.last = y1;
		buf.short5 = (arg1[1] << 3) | (arg1[2] >> 5);
		memcpy(frame, buf, 11);
	} else {
		memcpy(frame, buf, 11); // XXX loading uninitialized RAM???
	}
}

bool frame_enqueue_2612(struct message) {
	if (msgs_waiting_102e5e != 0) {
		msg_queue_head_102a11[msgs_waiting_102e5e++] = message;
		return true;
	} else {
		return false;
	}
}

bool is_whole_msg_waiting_26e3() {
	short y1 = msg_total_length_2654();
	char topNibble = msg_queue_head_102a11.nibble1;
	if (topNibble == 1) {
		rx24 = 4*((2 * y1 / 7) + y1) + 1; // calculate how many messages we need
		if (msgs_waiting_102e5e >= rx24) return true; // we have enough
		else return false;
	} else {
		if (msgs_waiting_102e5e) return true;
		else return false;
	}
}

void eeprom_process_msg_1094(char* buffer, short arg1) {
	char y1;
	// buffer is at Y+2..3
	// arg1 is at Y+4..5
	if (buffer[0] == 0x3d || buffer[0] == 0x27 || buffer[0] == 0x31) {
		y1 = 0x87;
		if (buffer[0] == 0x27) {
			y1 = eeprom_unlock_dc8(buffer, arg1);
			// if (y1 != 0x78) remember_and_die();
		} else if (eeprom_write_lock_1020f0 != 0x3c) {
			can_send_error_110c(0x33);
		} else if (buffer[0] == 0x31) {
			eeprom_reset_msg_1006(buffer, arg1);
		} else if (buffer[0] == 0x3d) {
			eeprom_write_msg_cfc(buffer, arg1);
		}
	} else {
		can_send_error_110c(0x11);
	}
}

char eeprom_unlock_dc8(char *buffer, short arg1) {
	// stack frame 0x1f -- 31
	char y1;        // Y+1
	short y2;       // Y+2..3 - more checks
	short y4;       // Y+4..5 - more checks
	char ret;       // Y+6
	char check;     // Y+7 - xor checks to avoid remember_and_die()
	char data1[10]; // Y+0x8..0x11
	char data2[8];  // Y+0x12..0x19
	char data3[2];  // Y+0xa..0xb
	// buffer is at    Y+0x1c..0x1d
	// arg1 is at      Y+0x1e..0x1f

	ret = 0x0087;
	if (0 == (buffer[1] & 1)) {
		if (arg1 >= 0) {
			sub_9ac();
			byte_1020f1 = 0x5a;
			memset(data1, 0, 8);
			data1[0] = 0x67;
			data1[1] = buffer[1] & 0x3f;
			memcpy(&data1[2], array_1025bc, 8);
			j_can_send_666_111f(data1, 10);
			byte_1025c4 = 0;
			return ~ret;
		} else {
			can_send_error_110c(0x13);
			return ~ret;
		}
	} else {
		if (byte_1020f1 != 0x5a) {
			can_send_error_110c(0x24);
			return ~ret;
		} else if (byte_1025c4 >= 4) {
			sub_9ac();
			can_send_error_110c(0x24);
			return ~ret;
		} else if (arg1 >= 11) {
			can_send_error_110c(0x13);
			return ~ret;
		} else {
			byte_1025c4 += 1;
			memcpy(data2, &buffer[2], arg1-2);
			y1 = sub_882(data2);
			if (y1 == 0x1e) {
				memset(data3, 0, 2);
				data3[0] = 0x67;
				data3[1] = buffer[1] & 0x3f;
				j_can_send_666_111f(data3, 2);
				return ~ret;
			} else if (byte_1025c4 == 4) {
				can_send_error_110c(0x35);
				return ~ret;
			} else {
				can_send_error_110c(0x36);
				sub_9ac();
				return ~ret;
			}
		}
	}
}

void eeprom_reset_msg_1006(char *msg, short msgLen) {
	char check;     // Y+1 -- xor or die accumulator
	char buffer[5]; // Y+2..6
	// msg is at       Y+7..8
	// msgLen is at    Y+9..0xa

	if (eeprom_write_lock_1020f0 != 0x3c) remember_and_die();
	if (msgLen != 4) {
		can_send_error_110c(0x13);
	} else if (msg[1] != 1) {
		can_send_error_110c(0x12);
	} else if (msg[2:3] != 0x0143) {
		can_send_error_110c(0x31);
	}
	eeprom_invalidate_cert_fb6();
	memset(buffer, 0, 5);
	buffer[0] = 0x71;
	buffer[1] = msg[1] & 0x3f;
	buffer[2] = msg[2];
	buffer[3] = msg[3];
	buffer[4] = 1;
	j_can_send_666_111f(buffer, 5);
}

void eeprom_invalidate_cert_fb6() {
	char check;      // Y+1 -- xor or die accumulator
	char buffer[16]; // Y+2..0x11

	if (eeprom_write_lock_1020f0 != 0x3c) remember_and_die();
	memset(buffer, 0xff, 16);
	eeprom_write_block(buffer, 0x1028, 16);
}

void eeprom_write_msg_cfc(char *buffer, short bufLen) {
	/* buffer looks like:
		0: ???
		1: 0x20, 0x21, or 0x22
		2,3: data, 2 bytes, length in y2
		4,5: data, 0..2 bytes, length in y3

	   bufLen should be 2+y2+y3+b4
	 */
	char y1;        // Y+1
	char y2;        // Y+2
	char y3;        // Y+3
	char *data;     // Y+4..5
	char rc;        // Y+6
	void *eeprom_addr; // Y+7..8
	short eeprom_len;  // Y+9..a
	// buffer is at    Y+0xb..0xc
	// bufLen is at    Y+0xd..0xe
	if (eeprom_write_lock_1020f0 != 0x3c) remember_and_die();

	if (arg < 6) {
		can_send_error_110c(0x13);
		return;
	}

	y1 = buffer[1];
	y2 = y1 & 0xf;
	y3 = y1 >> 4;
	if (y2 != 2) {
		can_send_error_110c(0x31);
		return;
	}

	eeprom_addr = buffer[2:3];
	if (y3 >= 3) {
		can_send_error_110c(0x22);
		return;
	}

	memset(&eeprom_len, 0, 2);
	if (bufLen < 2 + y2 + y3) {
		can_send_error_110c(0x13);
		return;
	}

	memcpy(&eeprom_len, &buffer[y2+2], y3);
	if (bufLen < 2 + y2 + y3 + eeprom_len) {
		can_send_error_110c(0x13);
		return;
	}

	data = &buffer[2 + y2 + y3 + eeprom_len];
	rc = eeprom_write_arbitrary_block_ca3(data, eeprom_addr, eeprom_len);
	if (rc != 1) {
		can_send_error_110c(0x31);
		return;
	}

	buffer[0] = 0x7d;
	j_can_send_666_111f(buffer, 2 + y2 + y3);
}

char eeprom_write_arbitrary_block_ca3(char *data, void *eeprom_addr, short length) {
    char y1 = 0;       // Y+1
	char y2 = 0x96;    // Y+2
	char y3 = 0x96;    // Y+3
	char y4 = 0x96;    // Y+4
	char y5 = 0x96;    // Y+5
	// data is at      Y+6..7
	// eeprom_addr at  Y+8..9
	// length is at    Y+a..b

	y2 = eeprom_valid_addr_len_be1(eeprom_addr, length);
	if (y2 != 0x69) return 0;
	y3 = eeprom_valid_addr_len_be1(eeprom_addr, length);
	if (y2 != 0x69) remember_and_die();

	eeprom_write_block(data, eeprom_addr, length);
	y1 = 1;
	if (y2 != 0x69) remember_and_die();
	return y1;
}

char eeprom_valid_addr_len_be1(void *eeprom_addr, short length) {
	char check;     // Y+1 -- initiall 0x25, later 0x52
	char ret;       // Y+2
	// eeprom_addr at  Y+3..4
	// length is at    Y+5..6

	ret = 0x96;
	if (eeprom_addr + eeprom_len < eeprom_addr) {
		return ret;
	} else if (eeprom_len >= 0x401) {
		return ret;
	} else if (eeprom_addr < 0x0040 || 0x0441 <= eeprom_addr) {
		return ret;
	} else if (eeprom_addr + eeprom_len < 0x0040 || 0x441 <= eeprom_addr + eeprom_len) {
		return ret;
	}

	ret = 0x69;
	return ret;
}

void try_readMessageBuffer_2575(void) {
	char ret; // Y+1
	canframe frame; // Y+2..0xC
	ret = readMessageBuffer_29a7(frame);
	if (ret) {
		possible_store_cert_eeprom_77EB(0x2137, frame.short5, frame.last, frame); // XXX WTF?
	} else {
		printf("Failed to read message buffer");
		die();
	}
}

char readMessageBuffer_29a7(char msg[11]) {
	if (byte_102e5d == 0) return 0;
	memcpy(msg, struct_1025c5, 11);
	byte_102e5d -= 1;
	memmove(struct_1025c5, word_1025d0, byte_102e5d * 11); // advance queue
	return 1;
}

void cert_process_msg_66c8(void *arg0, void *arg1) {
	// arg0 at Y+1..2
	// arg1 at Y+3..4
	if (cert_lock_102e61 == 11) {
		parse_cert_6481(arg0, arg1);
	} else if (cert_lock_102e61 != 0) {
		printf("Message received, sharing climate control settings.");
		sub_666d(0x210c, 5);
	}
	return;
}

void sub_666d(void *arg0, short five) {
	// stack frame 8
	short unused;    //  Y+1..2
	char buffer[36]; //  Y+3..4
	// arg0 is stored at Y+5..6
	// five is stored at Y+7..8
	rx14 = rx16 = $sp;
	{
		unused = 0x20+five-1;
		$sp -= (0x20+five); // stack alloc 37 bytes
		buffer = $sp+1;
		sub_2af8(arg0, five, buffer+five);
		memcpy(buffer, arg0, five);
		sub_61c1(buffer, 0x20+five, 0x01ff, 0x40);
	}
	$sp = r14;
	$sp = r16;
	return;
}

void sub_2af8(char *src, short offset, char* dest) {
	// stack frame 22 / 0x16
	char swap[16]; // Y+1
	// src      is at Y+0x11..12
	// offset   is at Y+0x13..13
	// dest     is at Y+0x15..16
	for (i=0; i<16; i++) {
		swap[i] = 0;
	}
	eeprom_read_block(&swap, 0x1028, 16);
	possible_hmac_4b03(dest, swap, 0x0080, src, offset << 3);
	return;
}

void possible_hmac_4b03(char *dest, char *temp, short eighty, char *src, uint32_t off8) {
	// possibly HMAC_SHA_256?
}

void parse_cert_6481(void *arg0, void *arg1) {
	// stack frame 9
	char y1; // Y+1
	char y2; // Y+2
	char y3; // Y+3
	char y4; // Y+4
	char y5; // Y+5
	// arg0 at  Y+6..7
	// arg1 at  Y+8..9
	if (cert_lock_102e61 != 11) {
		remember_and_die();
	} else if (*arg0 != 0x30) {
		printf("Certificate format not supported");
		die();
	} else if (arg1 < 64 || arg0[1]+2 != arg1) {
		printf("Key length not supported");
		die();
	}
	y1 = arg0[1]+2;
	/****/ if ( 0 == (y2=arg0[3]) || y2+5 < y1) {
		printf("Invalid length parameters");
		return 0xa4;
	} else if ( 0 == (y3=arg0[y2+5]) || y2+y3+7 < y1) {
		printf("Invalid length parameters");
		return 0xa4;
	} else if ( 0 == (y4=arg0[y2+y3+7]) || y2+y3+y4+9 < y1) {
		printf("Invalid length parameters");
		return 0xa4;
	} else if ( 0 == (y5=arg[y2+y3+y4+9]) || y2+y3+y4+y5+9 < y1) {
		printf("Invalid length parameters");
		return 0xa4;
	} else if (y5 != 0x31) {
		printf("Key length not supported");
		return 0xa4;
	} else {
		generate_session_key_2b8a(arg0+y2+y3+y4+10);
		cert_lock_102e61 = 0;
		printf("Session key initialized");
		return 0x4a;
	}
}

void generate_session_key_2b8a(void* arg0) {
	// stack frame 185
	void* y1;        // Y+1..2
	void* y3;        // Y+3..4
	char buffer[24]; // Y+5..28
	short y29;       // Y+29..30
	short y34;       // Y+34..35
	short y37;       // Y+37..48
	short y39;       // Y+39..40
	short y42;       // Y+42..43
	sessionKey sk44; // Y+44
	sessionKey sk69; // Y+69
	char bufTwo[24]; // Y+94..117
	char bufThr[24]; // Y+118..141
	// arg0 at          Y+184..185

	for (int i=0; i<24; i++) {
		buffer[i] = 0;
	}
	eeprom_read_block(buffer, 0x100a, 24);
	y29 = 24;
	y33 = &buffer;
	sub_2d61(y29);
	if (arg0[0]!=4) {
		printf("Error during session key generation");
		die();
	}
	y1 = arg0+1;
	y3 = arg0+25;
	y34 = 24;
	y39 = 24;
	y37 = y1;
	y42 = y3;

	sub_2d61(&y34);
	sub_2d61(&y39);
	if (j_init_struct_50a6(&sk44, 0xc0)) {
		printf("Insufficient memory");
		die();
	}
	sub_51a4(&sk44, &y34);

	if (j_init_struct_50a6(&sk69, 0xc0)) {
		printf("Insufficient memory");
		die();
	}
	sub_59d8(&sk69, &y29, &sk44, 0x20e8);

	for (int i=0; i<24; i++) {
		bufTwo[i] = 0;
		bufThr[i] = 0;
	}

	y142[0:1] = 24;
	y142[3:4] = &y94;
	y142[5:6] = 24;
	y142[8:9] = &y118;
	sub_521d(&y142, &sk69, 0x20e8);
	sub_6130(&y152, y142[3:4], 0, 24);
	eeprom_write_block(&y152, 0x1028, 16);
	return;
}
```

```c
/*** SUB 2720 ********************************************************/

short sub_2720(char* arg0) {
	// stack frame: 0x1c / 28
	short y1;       // Y+1..2
	short y3;       // Y+3..4
	char y5 = 0;    // Y+5
	short y6;       // Y+6..7
	short y8;       // Y+8..9
	char yA = 0;    // Y+10
	short yB;       // Y+11..12
	short yD;       // Y+13..14
	char yF;        // Y+15
	char y10[11];   // Y+16..26
	// char** arg0; // Y+27..28

	y5 = 0;
	while (3 == struct_102a11.nibble1) { // high nibble == 3
		memmove(msg_queue_head_102a11, byte_102a1c, msgs_waiting_102e5e * 11);
		msgs_waiting_102e5e -= 1;
	}
	if (0 == msg_queue_head_102a11.nibble1) {
		y6 = struct_102a11.short5;
		y8 = msg_total_length_2654();
		memcpy(arg0, byte_102a12, y8);
		memmove(msg_queue_head_102a11, byte_102a1c, msgs_waiting_102e5e*11);
		msgs_waiting_102e5e -= 1;
		return y6;
	} else if (2 == msg_queue_head_102a11.nibble1) {
		msg_new_2ac1(&y10, 2, 0, 0x500, 0, 0);
		yA = sub_296d(&y10, 1);
		if (yA==0) {
			try_readMessageBuffer_2575();
			sub_296d(&y10, 1);
		}
		memmove(msg_queue_head_102a11, byte_102a1c, msgs_waiting_102e5e*11);
		msgs_waiting_102e5e -= 1;
		return 0;
	} else { // == 1?
		yB = struct_102a11.short5;
		yD = msg_total_length_2654();
		memcpy(arg0, &struct_102a11.data, 6);
		for (y1 = 6, y3 = 1; y1 < yD; y3++) {
			Z = arg0 + y1;
			X = &msg_queue_head_102a11[y3];
			yF = sub_26a6(&arg0.data, X[0..10]); // param 2 in r12..r22
			y1 += yF
		}
		if (yD == 0 && msgs_waiting_102e5e != 0) {
			msgs_waiting_102e5e -= 1;
		}
		if (msgs_waiting_102e5e >= yD) {
			msgs_waiting_102e5e -= yD;
		} else {
			msgs_waiting_102e5e = 0;
		}
		memmove(msg_queue_head_102a11, msg_queue_head_102a11[y3], msgs_waiting_102e5e * 11 + 1);
		return yB;
	}
}

char sub_26a6(struct* dest, struct message) {
	char y1;
	// dest is Y+2..3
	// message is Y+4..Y+14
	y1 = (message.last & 0xF) -1;
	if (y1 < 9) {
		memcpy(dest, &message.second, y1);
		return y1;
	} else {
		return 0;
	}
}

struct *msg_new_2ac1(struct* arg0, char a1, char a2, short a3, char a4, char a5) {
	struct message;
	message.char_y1 = (a1 & 0xf) | 0x30;
	message.char_y2 = a2;
	message.char_y3 = a5;
	message.short_y9 = a3;
	message.char_yB = (a4 & 0xf0) | 3;
	for (i=0; i<11; i++) {
		arg0[i] = message[i];
	}
	return arg0;
}

short msg_total_length_2654(void) {
	short y1 = 0;
	char topNibble = msg_queue_head_102a11.nibble1;
	if (topNibble == 0) {
		y1 = (msg_queue_head_102a11.last & 0xf) - 1;
		if (y1<9) return y1;
		else return 0;
	} else if (topNibble == 1) {
		return ((msg_queue_head_102a11.nibble2) << 8) | msg_queue_head_102a11.char3;
	} else {
		return 0;
	}
}

char sub_296d(char *arg0, char arg1) {
	// char** arg0; // Y+1..2
	// char arg1;   // Y+3
	if (byte_102e5d + arg1 < 0x64) {
		memcpy(struct_1025c5[byte_102e5d], arg0, arg1 * 11);
		byte_102e5d += arg1;
		return 1;
	} else {
		return 0;
	}
}
```

```c
/*** INTERRUPTS ******************************************************/

void INT0_(void) {
	portb_output_set_74c7();
	sub_7904(some_sort_of_struct);
}

void INT1__0(void) {
	portb_output_set_74c7();
	sub_7904(byte_1021C1);
}

void portb_output_set_74c7(void) {
	PORTB_OUTSET = 1; // 0x625 -- "I/O Port Output Set"
}

void sub_7904(char *arg) {
	// char y1; // Y+1
	char y2;   // Y+2
	char sreg; // Y+3
	// arg is at  Y+4..5

	char sreg = *CPU_SREG; // Y+3
	disable_interrupts(); // always returns 1
	// note there's an omitted y1 that mediates a do{}while(false);

	y2 = sub_7b8b(arg[84], arg[86]) >> 6;
	if (y2 & 1) {
		arg[82] = (arg[82] + 1) % 8;
		rx24 = 14 * arg[82] + 0x12;
		sub_788d(arg, 0, &arg[rx24]);
	}

	if (y2 & 2) {
		arg[82] = (arg[82] + 1) % 8;
		rx24 = 14 * arg[82] + 0x12;
		sub_788d(arg, 0, &arg[rx24]);
	}

	restore_status_register(&sreg);
}
```

```c
/*** OTHER ***********************************************************/

sub_2d64(char arg0[]) {
	char i;  // Y+1
	char j;  // Y+2
	// arg0 at  Y+3..4
	if (arg[0:1]!=0 && arg0[arg0[0:1]-1]) {
		arg0[0:1] -= 1; // move arg0[0:1] to last non-NULL
	}
	if (arg[0:1]==0) {
		arg0[2] = '\0';
		return;
	}
	j = 7;
	i = arg0[3:4] + arg0[0:1] - 1;
	while (i>=0 && j!=0) {
		i <<= 1;
		j--;
	}
	//
	arg0[2] &= 0xf8;
	arg0[2] |= j;
}

char init_struct_50a9(sessionKey key, short size) {
	// arg0 at Y+1..2
	// size at Y+3..4
	arg0[3:4] = malloc(size);
	arg0[8:9] = malloc(size);
	arg0[13:14] = malloc(size);
	arg0[18:19] = malloc(size);
	arg0[23:24] = malloc(size);
	if (any of the above calls failed) {
		free(the ones that worked);
		return 1;
	} else {
		zero_arg0_35f2(arg0+0);
		zero_arg0_35f2(arg0+5);
		zero_arg0_35f2(arg0+10);
		zero_arg0_35f2(arg0+15);
		zero_arg0_35f2(arg0+20);
		return 0;
	}
}

void print_flag_8bb8( void(*usartC0_send_byte)(unsigned char) ) {
	// usartC0_send_byte is Y+6..7
	char i;   // Y+1
	void *y2; // Y+2..3
	char unused;  // Y+4
	char y5;  // Y+5
	for (i=0; i<32; i++) {
		y2 = flag_0x39e+i;
		y5 = unused = ROM:flag_0x39e[i];
		y5 ^= flag_array_102f01[i];
		usartC0_send_byte( y5 | ~flag_mask_102ef0 );
	}
}
```

```c
/*** OVERFLOW ********************************************************/

void cert_mask_flag_4de4(void) {
	// stack frame 0x114
	char check = 0;
	char block[16];  // Y+0x2..0x11
	char buffer[16]; // Y+0x12..0x21
	char rc1;        // Y+0x22
	char rc2;        // Y+0x23
	char rc3;        // Y+0x24
	char defCert[120];  // Y+0x25..0x9c
	char cert[120];  // Y+0x9d..0x114

	/** If EEPROM block at 0x1028 is initialized, return **/
	memset(block, 0, 16);
	// check ^= 1;
	eeprom_read_block(block, 0x1028, 16);
	memset(buffer, 0xff, 16);
	// check ^= 0x10;
	rc1 = strncmp(block, buffer, 16);
	if (rc1 != 0) return;

	/** If loaded cert not equal to default cert, mask out flag. **/
	rc2 = 0;
	memset(cert, 0, 120);
	// check ^= 2;
	eeprom_read_block(cert, 0x1040, 120);
	memcpy(defCert, cert_1022DB, 120);
	// check ^= 4;
	rc3 = strncmp(cert, defCert, 120);
	if (rc3 == 0) return;

	// if (rc1 != 0) remember_and_die();
	// check ^= 8;
	// if (rc3 == 0) remember_and_die();
	// if (check != 0x1f) remember_and_die();

	flag_mask_102ef0 = rc2; // hides flag, will show all 0xff after this line, but print_flag_or_die_4E8F fixes that
}

void cert_load_and_check_63e0(void) {
	// stack frame 0x112
	short y1;          // Y+1..2
	short unused;      // Y+3..4
	char *y5;          // Y+5..6
	char y7 = 0xa4;    // Y+7
	char y8[0x100];    // Y+8..0x107
	struct canframe y108; // Y+0x108..0x112

	memset(&y8, 0xff, 0x100);
	// test_const_rng_69e5();
	if (0 == cert_load_from_eeprom_61de(&y8)) { // safe
		printf("Invalid certificate size");
	}

	// test_const_rng_69e5();
	y7 = cert_check_valid_6297(&y8);
	// test_const_rng_69e5();
	if (y7 != 0x4a) {
		msg_new_2ac1(&y108, 2, 0, 0x0000, 0, 0);
		sub_77eb(0x2137, y108.short5, y108.last, &y108);
		detect_fi_worker_6A7C();
		printf("Loaded invalid certificate");
		die();
	}

	rx14 = $sp;
	{
		y1 = y8[1]+2;
		$sp -= (y1-1); // stack allocation based on input array
		y5 =  $sp + 1;
		memcpy(y5, &y8, y1);
		sub_61c1(y5, y1,  0x777, 0x40);
		cert_lock_102e61 = 11;
	}
	$sp = rx14;
}

char cert_load_from_eeprom_61de(char* arg) { // sub_61e2
	char y1;        // Y+1
	char unused;    // Y+2..3
	char check = 0; // Y+4
	// arg is at       Y+5..6

	// test_const_rng_69e5();
	// check ^= 1;
	y1 = eeprom_read_byte(0x1041)+2;
	// test_const_rng_69e5();
	// check ^= 2;
	// if (check == 0) return 0;

	// check ^= 4;
	// test_const_rng_69e5();
	// check ^= 8;
	eeprom_read_block(arg, 0x1040, y1);

	// check ^= 0x10;
	// test_const_rng_69e5();
	// if (check != 0x1f) remember_and_die();
	// test_const_rng_69e5();
	// if (check != 0x1f) remember_and_die();
	return arg;
}

char cert_check_valid_6297(char cert[0x100]) {
	// stack frame 0x132
	char buffer1[100]; // Y+0x1..0x64
	char buffer2[100]; // Y+0x65..0xc8
	char buffer3[100]; // Y+0xc9..0x12c
	char ret;          // Y+0x12d
	char len1;         // Y+0x12e
	char len2;         // Y+0x12f
	char len3;         // Y+0x130
	// p_cert is at       Y+0x131..0x132

	memset(buffer1, 0, 100);
	memset(buffer2, 0, 100);
	memset(buffer3, 0, 100);
	ret = 0xa4;
	// test_const_rng_69e5();

	if (cert[0] != 0x30) return 0xa4;
	// test_const_rng_69e5();

	len1 = cert[3];
	if (len1 == 0) return 0xa4;
	memcpy(buffer1, &cert[4], len1);

	len2 = cert[len1+5];
	if (len2 == 0) return 0xa4;
	memcpy(buffer3, &cert[len1+6], len2); // XXX overflow?

	len3 = cert[len1+len2+7];
	if (len3 == 0) return 0xa4;
	memcpy(buffer2, &cert[len1+len2+8], len3);

	// note, the checks below don't check null terminators...
	ret = cert_check_Riscar_CA_6236(buffer1);
	if (ret != 0x4a) return 0xa4;

	ret = cert_check_Nist_P192_627B(buffer3);
	if (ret != 0x4a) return 0xa4;

	ret = cert_check_abba_6252(buffer2);
	return ret;
}

char cert_check_abba_6252(char buffer[100]) {
	char block[8];
	eeprom_read_block(block, 0x1001, 8);
	rx24 = strncmp(block, buffer, 8);
	if (rx24 == 0) return 0x4a;
	else return 0xa4;
}
```

Structs:
```c
struct canframe {
	char:4  nibble1; // 1 -> multipart message
	char:4  nibble2; // first 4 bits of 12 bit msg size, with char3
	char    char3;
	char[6] data;
	short   short5;
	char    last;
}

struct sessionKey {
	short s1;
	char  c1;
	char  buf1[192];
	short s2;
	char  c2;
	char  buf2[192];
	short s3;
	char  c3;
	char  buf3[192];
	short s4;
	char  c4;
	char  buf4[192];
	short s5;
	char  c5;
	char  buf5[192];
};
```

## High Level Overview:
main_500e()
	* basic init, as always
	* 6f9a() -- loads Userid from NVM, possibly more?
	* 4f91() -- possibly load certs from NVM?
	* printf("Initializing...\n");
	* 671e() -- more init?
	* init_eeprom_certs_65c1() -- check eeprom certs are sane, if not load defaults
	* printf("Initialization complete\n");
	* main_loop_2c8b()
	* printf("==END==\n");

main_loop_2c8b()
	*

I've labelled a function "brick_and_die", but it might just wipe out progress
	* It sets a flag that causes detect_fi() to take the slow path
	* renamed remember_and_die()

We enable interrupts...
	* 0x56 -> INT0__
		- PORTE_INT_base?
	* 0x58 -> INT1__0

Get the right manual, go to page ~426, find the base address, follow link.

ROM:0x24e -- 0..F0..F (32 bytes) is at
ROM:0x27e -- sha256 h0..h7 values
ROM:0x29e -- sha256 h[0..63] values
ROM:0x39e -- The (obscured) flag
ROM:0x3bf -- a uint32_t that has something to do with the flag

Win condition is to:
	1. set `must_be_1337_10210A = 0x1337`
	2. call `print_flag_or_die_4E8F()`
Neither of those are referenced...

Possible inroads:
	- look at all EEPROM sites, might be able to learn something
		- script based on 0x101??? comments?
	- we have a some printf()s related to message recipt -> backtrace
	- look for overflows: memcpy, memmove, printf
		- also general search for X+, Y+, Z+
		- nope, too many to just check them all out

## Call Graphs
main_500e
	sub_671e -- these two are the calls between "Initializing..."
	init_eeprom_certs_65c1 -- and "Initialization complete"
		cert_mask_flag_4de4
		cert_load_and_check_63e0 -- "Invalid certificate size", "Loaded invalid certificate"
			cert_check_valid_6297
				cert_check_Riscar_CA_6236 -- "Riscar CA"
				cert_check_Nist_P192_627B -- "NIST P-192"
				cert_check_abba_6252 -- byte string
			sub_61c1 -> sub_2873 -> sub 28c9
				cert_something[123] -- "Unexpected length parameter"
	main_loop_2c8b
		cert_process_msg_66C8 -- "Message received, sharing climate control settings."
			parse_cert_6481 -- "Certificate format not supported", "Key length not supported", "Invalid length parameters", "Session key initialized"
				generate_session_key_2b8a --  "Error during session key generation", "Insufficient memory"
			sub_666d
		sub_2720
			try_readMessageBuffer_2575 -- "Failed to read message buffer" && die

main_loop_2c8b
	frame_read_25a0
	frame_enqueue_2612
	is_whole_msg_waiting_26e3 -> msg_total_length_2654
	msg_total_length_2654
	sub_2720
		* many
	cert_process_msg_66c8
		parse_cert_6481
			generate_session_key_2b8a
	eeprom_process_msg_1094
		eeprom_unlock_dc8
		eeprom_reset_msg_1006
		eeprom_write_msg_cfc
			eeprom_write_arbitrary_block_ca3
				- eeprom_write_block
	try_readMessageBuffer_2575
		readMessageBuffer_29a7

## Patching with r2
```sh
[0x00000000]> e asm.cpu =?
...
ATxmega128a4u
[0x00000000]> e asm.cpu = ATxmega128a4u
[0x00000000]> 0xd400
[0x0000d400]> pd 8
       ::   0x0000d400      8f3f           cpi r24, 0xff
       ::   0x0000d402      9105           cpc r25, r1
       `==< 0x0000d404      91f3           breq 0xd3ea
        `=< 0x0000d406      88f3           brcs 0xd3ea
            0x0000d408      0e94316d       call 0xda62
            0x0000d40c      8d83           std y+5, r24
            0x0000d40e      9e83           std y+6, r25
            0x0000d410      2981           ldd r18, y+1
[0x0000d400]> oo+
[0x0000d400]> wx 8130
[0x0000d400]> pd 8
       ::   0x0000d400      8130           cpi r24, 0x01
       ::   0x0000d402      9105           cpc r25, r1
       `==< 0x0000d404      91f3           breq 0xd3ea
        `=< 0x0000d406      88f3           brcs 0xd3ea
            0x0000d408      0e94316d       call 0xda62
            0x0000d40c      8d83           std y+5, r24
            0x0000d40e      9e83           std y+6, r25
            0x0000d410      2981           ldd r18, y+1
[0x0000d400]> wa  cpi r24, 0x10
Written 2 byte(s) ( cpi r24, 0x10) = wx 8031
[0x0000d400]> pd 8
       ::   0x0000d400      8031           cpi r24, 0x10
       ::   0x0000d402      9105           cpc r25, r1
       `==< 0x0000d404      91f3           breq 0xd3ea
        `=< 0x0000d406      88f3           brcs 0xd3ea
            0x0000d408      0e94316d       call 0xda62
            0x0000d40c      8d83           std y+5, r24
            0x0000d40e      9e83           std y+6, r25
            0x0000d410      2981           ldd r18, y+1
```

Description:
	- e -- muck around with variables, cpu is set wrong, have to fix
	- o -- muck around with files
	- oo+ -- reopen current file, in RW
	- w -- write
	- wx -- write give hex string to current position
	- 0xd400 -- move around
	- pd 8 -- print disassembly, 8 lines

## Simulated Runs:
Breakpoints:
	7226 / 0xe44c usart_print
	2c8b / 0x5916 main_loop_2c8b

### Patches:
	6a00 / 0xd400 -- 8f3f -> 8330
	6d4b / 0xda96 -- 8d83 -> 8f70 90e0 8b83 1c82 8d83 1e82
	92e5 / 0x125ca -- e0ec f1e0 -> 682f 70e1 fb01 2083 0196 0895
```sh
	# patch const RNG test to iterate 3 times instead of 255 times
	0x6a00*2
	wa  cpi r24, 0x03

	# patch test RNG `rx24` times to `and` rx24 with 0x000f to reduce count
	0x6d4b*2
	"wa  andi r24, 0x0f; ldi r25, 0x00; std y+3, r24; std y+4, r1; std y+5, r24; std y+6, r1"

	# patch eeprom block reads to come from RAM:0x3200 instead
	0x92c7*2
	wa  sbci r23, -0x32

	# patch eeprom byte reads to come from RAM:0x3200 instead
	0x92d8*2
	wa  sbci r31, -0x32

	# patch eeprom writes to go to RAM:0x3200
	0x92e5*2
    "wa movw r22, r24; ldi r19, 0x32; add r23, r19; movw r30, r22; st z, r18; adiw r24, 0x01; ret"

	# write a 0xff to 0x3200 so that we don't have to go through FI slow startup
	0x6778*2
	"wa ser r24; sts 0x3200, r24; ldi r24, 0; ldi r25, 0; call 0x12594; std y+3, r24; std y+1, r1; std y+2, r1; nop"

```

### --
Issue: Simulator doesn't do EEPROM writes
Solution: Find another spot and patch it to write there...
	- BSS ends at 0x3081, so I could use 0x3100+

## Payload
In order to win the challenge we need:
	1. to call sub_4e8f()
	2. with RAM:0x210a set to 0x1337

Neither of which are referenced, further, this is a Harvard architecture, so we can't execute arbitrary code. We need to ROP.

Key Gadgets:
	* Function INT0_ at ROM:79F5 populates r18-r31, r0, r1, SREG, and the RAMPs. If we have a relatively large payload size this makes it trivial to populate the registers as we need
	* ROM:3514: store rx18 to Z or rx24 (choice)

Other Gadgets:
	* loc_2606: copy r18 byte from Z to X, etc
	* loc_2ab5: copy r20 byte from Z to X, etc
	* ... lots of these
	* memmove, memcpy: copy rx20 bytes from rx22 to rx24

## Finding the Injection Point
To "smash the stack", we need an unbounded write to a stack array. Which means we're looking for Z+, Z- or similar.

Candidates:
	* memmove
	* memcopy

Other possibilities:
	* malloc/free
	* _ultoa_invert

### memmove()
	* sub_33b5
	* sub_34e2
	* sub_351c
	* sub_5bb3

### memcpy()
	* sub_20a
	* eeprom_write_msg_cfc
	* frame_read_25a0
	* sub_26a6
	* sub_2720
	* cert_something[123]
	* sub_2ee4
	* sub_3604
	* sub_3ac4
	* sub_3dbb
	* sub_3fee
	* sub_47b7
	* sub_49dc
	* possible_hmac_4b03
	* sub_5f40
	* cert_check_valid_6297
	* cert_load_and_check_63e0
	* sub_666d - no.

### cert_check_valid_6297
I think I can overflow this, I need to set buffer1 and buffer2 small,because the total needs to be less than 256 bytes (possibly 254), but each chunk can overflow a 100 byte buffer, so I could easily get 100 bytes of overflow, which should be enough to exploit.

## Getting my Payload to the Injection Point
I need to drop ~200 bytes at EEPROM:0x40 (aka 0x1040).

Things that write there:
	load_default_cert_4eea
		- writes the default certs that I have in my load
	maybe eeprom_write_arbitrary_block_ca3
		- writes to Y+8..9, which is argument rx22
		- comes from eeprom_write_msg_cfc, Y+7..8, which is Y+(B..C)[2], which is argument rx24
		- comes from eeprom_process_msg_1094, Y+2..3, which is argument rx24
		- comes from main_loop_2c8b, Y+9..10
		- possible, not easy to check

### Can Fuzzing:
When I spam enough crap at the CANBUS, I get back error frames. That's good. That happens because we're getting responses from the CAN controllers, but, we're out of sync. Bus contention is crapping out the frames.

I'm trying to guess what the bitrate of the controllers is:
	- 5.5 us
	- 1.5 us
	- 1.833 us
	- 4.583 / 11.42 -> 6.66 / 9.33

I want a signal like:
	- 43434343434343

Consider raw CAN traffic:
	0             Start Frame
	011.0011.0010 Arbitration: 0x332
	000           RTR, IDE, r0
	1000          Length: 8 bytes
	64 bits       Data: 8 bytes worth
	15 bits       CRC
	111           1, ACK, 1, EOF...

What do I see:
	a 1.167 us pulse after EOF -> possible 800 kHz signal? Possible 857 kHz signal?
	Pulse width 4us

Binary Search:
	When I send with a bitrate of 250,000 I transmit and get error frames
	300,000 -- error frame
	350,000 -- nil
	When I send with a bitrate of 500,000 it doesn't seem to do anything.

### Reading the SPI
I'm not liking fuzzing. Lets try looking at the SPI:                               __
Reading the MCP25625 data sheet, the way it works is we drop the chip-select line (CS aka Enable), then send one byte to indicate command. They send some number of data bytes for that command, then raise the Enable line.

Notable Commands:
	0x03 Read
	0x02 Write -- arg0 is address, arg1..n are data. If n>1 arg0 is incremented for each
	0x05 Bit Modify -- arg0 is addres, arg1 is register mask, arg2 is byte

Actual Commands:
	0x02 0x0f 0x80                 Write CANCTRL set configuration
	0x02 0x28 0x05 0xbb 0xc4       Write CNF3 ...
									     CNF3 0x05: PHSEG2 = 0x5 (PS2 Length bits)
									     CNF2 0xbb: use PHSEG2, sample once, PHSEG1=7, PRSEG=3
									     CNF1 0xc4: SJW=4xTq, BRP=4 -- Tq = 10/Fosc
	0x02 0x0f 0x00                 Write CANCTRL set normal

	0x02 0x0f 0x80                 Write CANCTRL set configuration
	0x02 0x00 0xcc 0xa0 0x00 0x00  Write RXF0SIDH: SID filter bits, first 11 bits are CAN id filter
									     1100.1100.101 -> 110.0110.0101 -> 0x665
	0x02 0x20 0xff 0xe0 0x00 0x00  Write RXM0SIDH: SID mask bits, first 11 bits are a mask
									     1111.1111.111 -> ... -> 0x7ff
	0x02 0x0f 0x00                 Write CANCTRL set normal

	0x02 0x0f 0x80                 Write CANCTRL set configuration
	0x05 0x2b 0x01 0x01            Bitset CANINTE RX0IE: interrupt when message received in RXB0
	0x05 0x2b 0x02 0x02            Bitset CANINTE RX1IE: interrupt when message received in RXB1
	0x02 0x0f 0x00                 Write CANCTRL set normal

So, my bitrate is composed of Tq -- time quanta
	1 Tq for sync
	3 Tq for propagation (PRSEG)
	7 Tq pre-sample time (PHSEG1)
	5 Tq post-samp time  (PHSEG2)
	16 Tq total per bit.

Which means it takes 160 clocks per bit... fun.
How fast is a clock? Possible external oscillator, on pin 20,21
	Possibly 16-25 MHz... schematic says a 16 MHz external oscillator

So, we know:
	1. bitrate is 100 kHz
	2. I need ot use a CAN id of 0x665

Try it:
```
	can0  666   [2]  01 11                     '..'
	can0  665   [8]  F1 E3 C7 8F 1E 3C 78 F0   '.....<x.'
	can0  666   [2]  01 11                     '..'
	can0  665   [8]  F1 E3 C7 8F 1E 3C 78 F0   '.....<x.'
	can0  666   [2]  01 11                     '..'
	can0  665   [8]  F1 E3 C7 8F 1E 3C 78 F0   '.....<x.'
	can0  666   [2]  01 11                     '..'
```
Success.

### More Can Fuzzing

Back to fuzzing:
	- packets starting with `F1 E3` get immediate responses
	- a packet starting `11 F1 E3` ate an enormous number of packets before getting a reply
	- mostly we get back `01 11`, occasional `01 33`
	- default 5x packets per second from `cangen` is too fast. Trying 1/s.
	-

```
  can0  665   [2]  F1 E3                     '..'
  can0  666   [2]  01 33                     '.3'
```

```
  can0  500   [3]  32 00 00                  '2..'
```

`eeprom_process_msg_1094` throws error codes 0x33 and 0x11 to `jmb_error_110c`
That invokes `sub_111c` with the address of them and 0x1 (length)

NOTE: The code also accepts 776.
```
  can0  776   [5]  04 27 11 22 33            '.'."3'
  can0  1FF   [8]  10 25 64 0D 25 50 32 47   '.%d.%P2G'
  can0  1FF   [8]  21 BD 08 6F 63 6F F2 10   '!..oco..'
  can0  1FF   [8]  22 9A E9 35 57 F4 11 F6   '"..5W...'
  can0  1FF   [8]  23 37 76 9F 46 1E E2 3F   '#7v.F..?'
  can0  1FF   [8]  24 A6 EA 23 7E 7A B7 09   '$..#~z..'
  can0  1FF   [4]  25 AA 70 8B               '%.p.'
```
That's because the SID selection is just a list of bits that MUST be set
So actual SID is `[67][67ef][57df]`

Testing:
	665 667 66d 66f 675 677 67d 67f 6e5 6e7 6ed 6ef 6f5 6f7 6fd 6ff 765 767 76d 76f 775 777 77d 77f 7e5 7e7 7ed 7ef 7f5 7f7 7fd 7ff

Results:
```
  can0  67D   [5]  04 27 11 22 33            '.'."3'
  can0  666   [8]  10 0A 67 11 B3 53 DB 97   '..g..S..'
  can0  67F   [5]  04 27 11 22 33            '.'."3'
  can0  666   [5]  21 00 00 00 00            '!....'
```
Note: something weird here.

### Happy Path

Todo:
	understand how main_loop_2c8b merges frames into messages
		-> sub_2720 is the thing that does that
	understand how sub_2720 works
	figure out what's up with readMessageBuffer_29a7()...

Phase 1:
	
	0. invoke eeprom_process_msg_1094() with a buffer starting with 0x27
	1. that invokes eeprom_unlock_dc8
		* which somehow sets eeprom_write_lock_1020f0 to 0x3c
	1. invoke eeprom_process_msg_1094() with a buffer starting with 0x3d
	1. which invokes eeprom_write_msg_cfc with a buff that writes my "cert" to EEPROM:0x1040
	2. eeprom_write_arbitrary_block_ca3 drops my cert to eeprom


Phase 2:
	1. reboot board
	2. cert_load_and_check_63e0 fires, loads my "cert" from EEPROM:0x1040
	3. invokes cert_check_valid_6297, which overflows
	4. return to INT0_ populates registers
	5. return to ROM:3514 makes us leet
	6. return to print_flag_or_die_4E8F and we win.
	7. submit flag
