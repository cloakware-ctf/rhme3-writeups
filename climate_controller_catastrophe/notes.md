
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

TODO: Oscilloscope, check for analogue signals.

## Reversing: Looking for I/O:
	* DACB_CTRLA -- lots of code, but at the end, uncalled
	* ADCA_CTRLA -- also referenced, but uncalled

## Decompilation
### init_4f91
```c
IN: r24 = 0xF0
OUT: rt24 == 0x0F || die()
char test_eeprom_4f91(char arg0) {
	// stack frame: 17 
	char x = arg0; // Y+1
	char buf1[8];  // Y+2
	char buf2[8];  // Y+10

	memset(buf1, 0, 8);
	eeprom_read_block(buf1, 1, 8); // EEPROM address 1
	memcpy(buf2, abba_10237A, 8);

	if (0==strncmp(buf1, buf2, 8)) {
		x = cert_4eea();
	}

	eeprom_read_block(buf1, 1, 8); // EEPROM address 1
	if (0==strncmp(buf1, buf2, 8)) {
		x = 0xf;
	} else {
		x = cert_4eea();
		// gonna die()
	}

	eeprom_read_block(buf1, 1, 8); // EEPROM address 1
	if (0 != strncmp(buf1, buf2, 8)) brick_and_die();
	if (0 != strncmp(buf1, buf2, 8)) brick_and_die();

	return x;
}

OUT: r24 = 0x0F
char test_write_eeprom_4eea(void) {
	// stack frame: 0xab
	char x = 1;        // Y+1
	char var_2 = 0;    // Y+2
	char var_3 = 0xf0; // Y+3
	char buf2[8];      // Y+4..12
	
	memcpy(buf2, abba_10237A, 8);
	// XXX
}
```

## High Level Overview:
main_500e()
	* basic init, as always
	* 6f9a() -- loads Userid from NVM, possibly more?
	* 4f91() -- possibly load certs from NVM?
	* printf("Initializing...\n");
	* 671e() -- more init?
	* printf("Initialization complete\n");
	* main_loop_2c8b()
	* printf("==END==\n");

main_loop_2c8b()
	* XXX TODO: reverse here

I've labelled a function "brick_and_die", but it might just wipe out progress

## Simulated Runs:
Breakpoints:
	7226 / 0xe44c usart_print
	???? / write_eeprom
		- need to do manually

Patches:
	6a00 / 0xd400 -- 8f3f -> 8330
	6d4b / 0xda96 -- 8d83 -> 8f70 90e0 8b83 1c82 8d83 1e82
	92e5 / 0x125ca -- e0ec f1e0 -> 682f 70e1 fb01 2083 0196 0895

Issue: Simulator doesn't do EEPROM writes
Solution: none.

