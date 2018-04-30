/*
 * A3uGlitcher.c
 *
 * Created: 2018-04-26 15:57:45
 * Author : jonathan.beverley
 */ 

#include <avr/io.h>
#include <stdio.h>
#include <avr/sfr_defs.h>
#define F_CPU 33680000UL // 16 MHz
#include <util/delay.h>

/**
 * @brief Configure the USART0 port.
 */
void serial_init() {
	// enable sending on PORTC3
	PORTC.OUTSET = PIN3_bm;
	PORTC.DIRSET = PIN3_bm;

	// enable receiving on PORTC2
	PORTC.OUTCLR = PIN2_bm;
	PORTC.DIRCLR = PIN2_bm;
	
	//Enable receive and transmit
	USARTC0.CTRLB = USART_CLK2X_bm; // double tx speed

	//8 data bits, no parity and 1 stop bit
	USARTC0.CTRLC = USART_CHSIZE_8BIT_gc; // 8N1

	// set baud 115200
	USARTC0.BAUDCTRLB = 0; // BScale = 0
	USARTC0.BAUDCTRLA = 0x23; // BSEL = 34 -> 115200, for some clock rate...
	USARTC0.CTRLB |= USART_RXEN_bm | USART_TXEN_bm;
}

/**
 * @brief Send a single byte.
 * @param[in] usart  Port to send on
 * @param[in] byte  Byte to send
 */
void usart_send_byte(USART_t* usart, uint8_t byte) {
	while ( (usart->STATUS & USART_DREIF_bm) == 0) {
		// wait until ready	
	}
	/* Send byte */
	usart->DATA = byte;
}

void serial_puts(char *string) {
	while (*string) {
		usart_send_byte(&USARTC0, *string++);
	}
}

/**
 * @brief Get incoming data.
 * @return Received byte.
 */
uint8_t usart_recv_byte(USART_t* usart) {
	/* Wait until data is available */
	while ( (usart->STATUS & USART_RXCIF_bm) == 0) {
		// wait until ready
	}

	/* Read byte */
	uint8_t byte = usart->DATA;
	
	usart_send_byte(usart, byte);
	return byte;
}

void setup_clock() {
	// enable 32MHz clock, and wait for it to be ready
	OSC_CTRL |= OSC_RC32MEN_bm;
	while ( (OSC_STATUS & OSC_RC32MRDY_bm) == 0 ) {
		/**/
	}
	
	// setup system to use it
	CPU_CCP = CCP_IOREG_gc;
	CLK_CTRL = CLK_SCLKSEL_RC32M_gc | CLK_PSADIV_1_gc;
	
	// why we do this?
	OSC_CTRL &= ~OSC_RC2MEN_bm;
}

// delay in clocks = (2063 ns / 1e9) * clock-per-second
#define cyclesPerMS (F_CPU / 1000)
const uint8_t ConfiguredOffset = ((2063 * cyclesPerMS) / 1000000) - 11; // offset in clocks (-11 is constant delay correction)
const uint8_t ConfiguredDelta = 1; // delta in clocks
const uint8_t OffsetLoopCost = 3;

#define NOP() do {__asm__ __volatile__ ("nop");}while(0)
#define PULSE(PORT, PIN) do { PORT.OUTSET = PIN; NOP(); NOP(); NOP(); PORT.OUTCLR = PIN; } while(0)
#define WAIT_FOR_TRIGGER() \
	do { \
		while (bit_is_clear(PORTB.IN, PIN1_bp)) { /**/ } \
		if (bit_is_clear(PORTB.IN, PIN1_bp)) continue; \
		break;  \
	} while(1)

#if 0
	#define MARKERPULSE() PULSE(PORTB, PIN0_bm)
	#define MarkerWarning() serial_puts("WARNING: Marker pulses enabled!\n")
#else
	#define MARKERPULSE() 
	#define MarkerWarning() 
#endif

void glitchPlusZero(uint8_t offset) {
	WAIT_FOR_TRIGGER();
	MARKERPULSE();
	while (offset!=0) offset--;
	PULSE(PORTB, PIN0_bm);
}

void glitchPlusOne(uint8_t offset) {
	WAIT_FOR_TRIGGER();
	MARKERPULSE();
	while (offset!=0) offset--;
	NOP();
	PULSE(PORTB, PIN0_bm);
}

void glitchPlusTwo(uint8_t offset) {
	WAIT_FOR_TRIGGER();
	MARKERPULSE();
	while (offset!=0) offset--;
	NOP();
	NOP();
	PULSE(PORTB, PIN0_bm);
}

void glitchPlusThree(uint8_t offset) {
	WAIT_FOR_TRIGGER();
	MARKERPULSE();
	while (offset!=0) offset--;
	NOP();
	NOP();
	NOP();
	PULSE(PORTB, PIN0_bm);
}

void glitch(uint8_t offset) {
	switch (offset%OffsetLoopCost) {
		case 0: glitchPlusZero(offset/OffsetLoopCost); break;
		case 1: glitchPlusOne(offset/OffsetLoopCost); break;
		case 2: glitchPlusTwo(offset/OffsetLoopCost); break;
		case 3: glitchPlusThree(offset/OffsetLoopCost); break;
	}
}

void glitchExplorer(void) {
	uint8_t offset;
	uint8_t o;
	
	PORTB.DIRCLR = PIN1_bm | PIN2_bm; // only pins A0, A1 to input, rest left out
	PORTB.PIN1CTRL = PORT_OPC_PULLDOWN_gc;
	PORTB.PIN2CTRL = PORT_OPC_PULLDOWN_gc;

	PORTB.DIRSET = PIN0_bm; // set pin B0 to input
	PORTB.PIN0CTRL = PORT_OPC_PULLDOWN_gc;
	PORTB.OUTCLR = PIN0_bm;
		
	serial_puts("I'm waiting on you\n");
	for (o=1; ; o++) {
		MarkerWarning();
		if (o%2 == 1) {
			offset = ConfiguredOffset + ConfiguredDelta * (o/2);
			} else {
			offset = ConfiguredOffset - ConfiguredDelta * (o/2);
		}
		if (offset < 1) continue;
		glitch(offset);
		serial_puts("glitch sent\n");
		_delay_ms(1000);
	}
}

int main(void) {
	setup_clock();
	serial_init();
	
	// TODO: use serial to get config.
	
	if (ConfiguredOffset<=0 || ConfiguredDelta<=0) {
		serial_puts("Invalid parameters!\n");
		while(1);
	}
	
	glitchExplorer();
	return 0;
}

