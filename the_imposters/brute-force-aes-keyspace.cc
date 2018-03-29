
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void xxd(const uint8_t *buffer, int length) {
	for (int line=0; line<length; line+=16) {
		printf("%08x: ", line);
		for (int byte=line; byte<length && byte<line+16; byte++) {
			printf("%02x ", buffer[byte]);
		}
		if (line/16 == length/16) {
			for (int pad=length%16; pad<16; pad++) {
				printf("   ");
			}
		}
		printf(" ");
		for (int byte=line; byte<length && byte<line+16; byte++) {
			uint8_t c = buffer[byte];
			if (c<32 || 127<c) c = 0x2e; // '.'
			printf("%c", c);
		}
		printf("\n");
	}
}

const uint8_t testKey[16] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, };
const uint8_t testPlain[16] = {
	0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x69, 0x73, 0x20, 0x6c, 0x65, 0x74, 0x74, 0x65, 0x72, 0x73, };
const uint8_t testEnc[16] = {
	0x20, 0xf7, 0xf1, 0x19, 0x84, 0x0d, 0xa9, 0xea, 0xf7, 0xde, 0x55, 0xca, 0x01, 0x86, 0x97, 0x1e, };

const uint8_t bruteForceSpace[16][5] = {
	{4, 0x00, 0xc1, 0xe2, 0x16},
	{3, 0x40, 0x6a, 0x11,    0},
	{3, 0x22, 0x5f, 0x2e,    0},
	{2, 0x33, 0xc8,    0,    0},
	{2, 0x44, 0xc7,    0,    0},
	{2, 0x55, 0x44,    0,    0},
	{2, 0x66, 0x43,    0,    0},
	{2, 0x77, 0xbd,    0,    0},
	{2, 0x88, 0x9a,    0,    0},
	{2, 0x99, 0x11,    0,    0},
	{2, 0xaa, 0xfc,    0,    0},
	{2, 0xbb, 0xfb,    0,    0},
	{1, 0xcc,    0,    0,    0},
	{1, 0xdd,    0,    0,    0},
	{1, 0xee,    0,    0,    0},
	{1, 0xff,    0,    0,    0},
};

int main(int argc, char** argv) {
	const uint8_t *plaintext = testPlain;
	const uint8_t *target = testEnc;

	AES_KEY schedule;
	uint8_t key[16];
	uint8_t counter[16];
	uint8_t ciphertext[16];

	uint64_t difficulty=1;
	for (int i=0; i<16; i++) {
		difficulty *= bruteForceSpace[i][0];
	}
	printf("brute forcing %lu candidates.\n", difficulty);

	int n=0;
    memset(counter, 1, 16);
	printf("--------");

	while (true) {
        for (int i=0; i<16; i++) {
			key[i] = bruteForceSpace[i][counter[i]];
		}

		AES_set_encrypt_key(key, 128, &schedule);
		AES_encrypt(plaintext, ciphertext, &schedule);

		if (0 == memcmp(ciphertext, target, 16)) {
			printf("\n*** HIT! ***\n");
			xxd(key, 16);
			xxd(ciphertext, 16);
			xxd(target, 16);
			printf("--------");
		} else {
			printf("%8d", n++);
		}

		for (int i=0; i<16; i++) {
			counter[i] += 1;
			if (counter[i] <= bruteForceSpace[i][0]) break;
			counter[i] = 1;
			if (i<15) continue;
			if (i==15) return 1;
		}
	}
	printf("\n");

	return 0;
}
