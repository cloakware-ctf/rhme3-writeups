
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
	serial_printf("CO2 level regulator booted.\n");
	for (;;) {
		flag_set_mask_d52(0);
		sub_13b();
		randomize_randomarray();
		word_1020bd = 0;
		byte_102000 = 0xff;
		change_filter();
		serial_printf(" applied successfully.\n");
	}
}

void sub_13b() {
	for (;;) {
		deadword_1020ba = 0xdead;
		word_1020bd = 0;
		for (;;) {
			if ((uint32_t)word_1020bd < random_dword()) {
				word_1020bd++;
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
	uint8_t array[16];
	for (word_1020bd = 0; word_1020bd < 16; word_1020bd++) {
		array[word_1020bd] = 0;
	}
	
	sub_1b4(&array, 16);
	serial_printf("What filter level do you want to apply?\n> ");
	byte_1020bc = sub_35a(USARTC0, &array, 0x20, '\n'); // OVERFLOW!
	// XXX I'm squishy here, not sure it's right...
	if (array[15] = '\0') {
		array[15] = byte_1020bc;
	}
	byte_102000 = sub_1d3(&array, 0x16); // what's with these sizes?
	sub_2f0(byte_102000) ;
	if (byte_102000 != 0) die();
	serial_printf("Filter level ");
	serial_printf(array); // format string vuln?
}

uint8_t sub_35a() {
	// XXX this is not the proper read_str_until function
	// but it's not the known-broken one either...
}

```
