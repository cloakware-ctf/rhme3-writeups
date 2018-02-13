
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

#
