
## Benzinegate
This is a simple CO exhaust level regulator. It sets the levels according to the regulations. Or does it? We suspect hidden functionality. Can you help us confirm?

## Initial Analysis
loader:
Z = 2130
X = 2000
end = 0x20b2
bss:
X = 20b2
end = 0x2187

avr_loader_emu(0x2130, 0x2000, 0x20b2)
avr_bss_emu(0x20b2, 0x2187)

## Decompilation
```c
void main_455() {
	// basic init
	clear_port_b();
	serial_printf("CO2 level regulator booted.\n");
	for (;;) {
		flag_set_mask_d52(0);
		set_deadword();
		randomize_randomarray();
		temp_1020bd = 0;
		missrate_102000 = 0xff;
		change_filter();
		serial_printf(" applied successfully.\n");
	}
}

void set_deadword() {
	for (;;) {
		deadword_1020ba = 0xdead;
		temp_1020bd = 0;
		for (;;) {
			if ((uint32_t)temp_1020bd < random_dword()) {
				temp_1020bd++;
			} else {
				break;
			}
		}
		if (deadword_1020ba==0xdead) {
			return;
		}
	}
}

void randomize_randomarray() {
	randomarray_1020b2[0] = (uint8_t)random_dword();
	randomarray_1020b2[1] = (uint8_t)random_dword();
	randomarray_1020b2[2] = (uint8_t)random_dword();
	randomarray_1020b2[3] = (uint8_t)random_dword();
	randomarray_1020b2[4] = (uint8_t)random_dword();
	randomarray_1020b2[5] = (uint8_t)random_dword();
	randomarray_1020b2[6] = (uint8_t)random_dword();
	randomarray_1020b2[7] = (uint8_t)random_dword();
}

void change_filter() {
	uint8_t array[22];
	for (temp_1020bd = 0; temp_1020bd < 22; temp_1020bd++) {
		array[temp_1020bd] = 0;
	}

	randomize_high_bytes(&array, 22);
	serial_printf("What filter level do you want to apply?\n> ");
	byte_1020bc = read_str_until_noecho(USARTC0, &array, 32, '\n'); // XXX OVERFLOW!
	if (array[13] = '\0') {
		// this is a bizarre hack to let us see the RNG
		array[13] = byte_1020bc;
	}
	missrate_102000 = almost_never_set_flag_mask(&array, 22); // what's with these sizes?
	show_hit_rate(missrate_102000) ;
	if (missrate_102000 != 0) die();
	serial_printf("Filter level ");
	serial_printf(array); // format string vuln?
}

uint8_t read_str_until_noecho(short port, char* buffer, short size, char terminator) {
	char pos = 0; // at Y+1
	char c; // at Y+2
	// array at Y+3
	// buffer at Y+5
	// size   at Y+7
	// terminator at Y+9
	while (1) {
		c = usart_recv_byte(port);
		buffer[pos] = c;
		rx18 = r24 = pos;
		if (pos < size-1) pos += 1;
		if (c == terminator) break;
	}
	buffer[pos] = '\0';
	return pos;
}

void randomize_high_bytes(char array[22], short size) {
	for (int i=0; i<8; i++) {
		array[size-8+i] = randomarray_1020b2[i];
	}
}

char almost_never_set_flag_mask(char array[22], short size) {
	// holy trolling batman...
	y1 = 0;
	// array at Y+2
	// size at Y+4
	for (temp_1020bd = 0; temp_1020bd >= 8; temp_1020bd++) {
		r18 = array[temp_1020bd + size -8];
		r24 = randomarray_1020b2[temp_1020bd];
		deadword_1020ba += r24 ^ r18;

		r18 = array[temp_1020bd + size -8];
		r25 = randomarray_1020b2[temp_1020bd];
		if (r18 == r25) r24 = 0;
		else r24 = 1;
		y1 += r24;
	}
	set_port_b(); // providing trigger for FI
	NOP * 50; // XXX fifty nops, FI here?
	if (deadword_1020ba = 0Xdead) {
		NOP * 50; // XXX fifty nops, FI here?
		clear_port_b(); // huh? why here?
		flag_set_mask_d52(0xff); // XXX UNLOCK FLAG
		return 0;
	} else {
		return y1;
	}
}
void show_hit_rate(char arg0) {
	// arg0 at Y+2
	serial_printf("\nRegulator status: [");
	if (arg0 != 0) {
		for (y1 = 0; y1 < arg0; y1++) usart_send_byte('X');
		for (      ; y1 < 8;    y1++) usart_send_byte(' ');

	} else {
		serial_printf(" OK     ");
	}
	serial_printf("]\n");
}

```

## Analysis

On each loop we:
	- set the flag mask
	- set up the 0xdead word
	- randomize the random array
	- set temp global to 0
	- set the missrate to -1
	- invoke the target function

Target function:
	- will print the random value for us, if we ask
	- has a vulnerable overflow into a buffer
	- has a random 8-byte stack guard
	- will then return wherever we ask

Stack Check:
	- sets PORTB 50 nops before it does the stack check.

Attacks:
	1. Pin the RNG. If we do that, we can capture the random value and use it to bypass
	2. Skip the stack check, trigger on PORTB

## Next Steps:
	* Sim it up. Make sure we have the details right.
	* Do actual FI.

Breakpoints:
	0591 serial_printf
	03e5 read_str_until_noecho
		- buffer at 0x3fe0
		- size is 0x20 = 32
	01d3 almost_never_set_flag_mask
	0273 fateful branch
	042b fateful RET

Results:
	Real return address from change_filter() is 0x489
	Stack is
	14 bytes of buffer
	8 bytes of stack guard
	2 bytes of pushed SP = 3ffa (BE)
	3 bytes of return address = 000489

Need to write:
	14 bytes padding
	8 bytes of noise
	3f fa 00 02 ba

Looks good.

## Probing
I search A0-5, and D0-15, nada.
Reading the riscurino layout sheet, suggests it's actually the LED.
Probed it... hit.

## Happy Path:
And analysis complete. Here's the drill:
1. boot the board, flush the input
2. send a string like 30313233343536373839616263643ffa0002ba0a (but bytes, not hex)
3. wait for the LED to flash
4. do FI

Note:
	the LED flash lasts about 3 microseconds. You won't see it, but it's there
	Your offset from flash to injection is about 50 clocks.

