
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
char init_load_eeprom_4eea(void) {
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
	* It sets a flag that causes detect_fi() to take the slow path

We enable interrupts...
	* 0x56 -> INT0__
		- PORTE_INT_base?
	* 0x58 -> INT1__0

Get the right manual, go to page ~426, find the base address, follow link.


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

