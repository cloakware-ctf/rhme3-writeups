
## Overview
```c
int main_9a5() {
	init_clock();
	some_init_a6b(); // more init
	short decoded = 0;  // Y+1,2
	short length = 256; // Y+3,4
	char  x = ?;        // Y+5
	char  unknown[5];   // Y+6..0xa -- 5 bytes
	// intially: 60 ed 82 39 43

	serial_printf("Black box connected\n");
	while (true) {
		x = menu_89d();
		serial_printf("Option: %d", x);
		switch(x) {
			case 1: // decrypt data
				if (decoded) {
					serial_printf("Already decoded!\n");		   
				} else {
					decrypt_data_8f1(unknown, length);
				}
				decoded = 1;
				break;
			case 2: // print data
				//print_data_955(unknown);
				printf("%s", unknown);
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
	char* buffer[??]; //Y+1
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

unsigned char array_102268[] = [
	0x44, 0x11, 0xBB, 0xCE, 0xF0, 0xAA, 0x4A, 0xB4,
	0xFA, 0x1A, 0xD1, 0x0A, 0xE0, 0x9B, 0xBD, 0x3D,
	0x88, 0xE3, 0x36, 0xD9, 0x47, 0x16, 0xEA, 0xD7,
	0x5C, 0x00, 0x41, 0xCF, 0xA1, 0xF7, 0xD9, 0x80
];
void decrypt_data_8f1(short buffer, short len) {
	// alloc 0xc6 on stack
	char* keyXX;   // Y+3     -- 160 bytes
	char* array;   // Y[0xa3] -- 32 bytes
	char* buffer;  // Y[0xc3]
	short length;  // Y[0xc5]
	for (i=0; i<32; i++) {
		array[i] = array_102268[i];
	}
	sub_207(keyXX, array);
	serial_printf("Decrypting data\n");

	for (short i=0; i<length; i+=16) {
		sub_702(keyXX, buffer+i)
	}
}

```

## Dynamic
Break:
	0b34 / 0x1668 -- printf()
	08e5 / 0x11ca -- read_str() callsite

On read_str():
	- buffer is 0x3efc
	- buflen is 3
	- all checks out, no overflow

Print Data:
	- prints from 0x3efc:
		0a 6d 0a 6d 6d 04 00 0a 2c 00 00 00 01 00 60 ed
		82 39 43 0c d9 c9 46 20 13 ab 10 e4 52 2d 30 06
	- 
