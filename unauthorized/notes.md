The python (garbage) scripts are doing pretty good right now.

I setup an idb starting with the hex file and auto-analysis disabled.

The codatify scripts didn't make 100% sense though when applied because there were many 16-bit elements in RAM which did not align on 16bit address boundaries.

After importing function names/comments using bindiff (it's actually working pretty well), I started looking at the strings.

There are many strings in here that are also in the *full compromise* challenge.

Then I started poking at `main`. There is an obvious series of branches which would lead to printing 'your flag is'. But it's not clear one could ever get the code to take that path. And... it's an exploitation challenge. So that's probably not the point anyways.

```
ldi     r22, 0x42 ; 'B'
ROM:0A7F                 ldi     r23, 0x21 ; '!' ; aYourFlagIs
ROM:0A80                 call    j_usart_print
ROM:0A82                 call    prob_safe_get_rand
ROM:0A84                 ldd     r24, Y+0x1D
ROM:0A85                 cpi     r24, 0x3F ; '?'
ROM:0A86                 breq    loc_A8A
ROM:0A87                 call    sub_3B6
ROM:0A89                 rjmp    loc_AA9
ROM:0A8A ; ---------------------------------------------------------------------------
ROM:0A8A
ROM:0A8A loc_A8A:                                ; CODE XREF: main+102j
ROM:0A8A                 call    prob_safe_get_rand
ROM:0A8C                 ldd     r24, Y+0x1D
ROM:0A8D                 cpi     r24, 0x3F ; '?'
ROM:0A8E                 breq    loc_A92
ROM:0A8F                 call    sub_3B6
ROM:0A91                 rjmp    loc_AA9
ROM:0A92 ; ---------------------------------------------------------------------------
ROM:0A92
ROM:0A92 loc_A92:                                ; CODE XREF: main+10Aj
ROM:0A92                 call    prob_safe_get_rand
ROM:0A94                 movw    r24, YL
ROM:0A95                 subi    r24, 0x19
ROM:0A96                 sbci    r25, -1
ROM:0A97                 movw    ZL, r24
ROM:0A98                 ld      r24, Z
ROM:0A99                 cpi     r24, 1
ROM:0A9A                 breq    loc_A9E
ROM:0A9B                 call    sub_3B6
ROM:0A9D                 rjmp    loc_AA9
ROM:0A9E ; ---------------------------------------------------------------------------
ROM:0A9E
ROM:0A9E loc_A9E:                                ; CODE XREF: main+116j
ROM:0A9E                 lds     r24, fn_ptr_ptr_for247A
ROM:0AA0                 lds     r25, fn_ptr_ptr_for247A+1
ROM:0AA2                 call    sub_247A        ; does eicall rx24
```

The function ```sub_247A``` prepares some arguments and then does a dispatch to a function point in globals of RAM

I found this function pointer pointer which would contain the address to the print flag function.
```
RAM:183A fn_ptr_ptr_for247A_0:.byte 2            ; DATA XREF: sub_68A+2DAt
RAM:183A                                         ; fn ptr ptr to print flag function
```

Maybe part of the challenge is to get the challenge binary to print or otherwise load this function address and jump to it.

I got an updated *full compromise* idb from Jonathan and used bindiff to import some function names.

I poked around the write eeprom functions and noticed that detect fault injection is writing a flag to address 0 of the eeprom.

I found also that what was marked as eeprom_mapen is actually implementing a read of eeprom address

I annotated all the callsites of the write and read of eeprom with the addresses to/from and the values when known. Eeprom is being used to preserve RNG test parameters and also to preserve FI tests.

The code that is testing someting and then optionally calling what I'm pretty sure is a flag printer, `ROM:068A test_something_and_set_flag_printer` is referring to malloc'd buffers of 100 34 byte structures; the last of which points to a 9byte buffer that gets the contents 'backdoor' as setup by `ROM:05DD setup_100_34b_structs_and_one_backdoor`

The function that reads in characters up to an expected terminator takes a maximum size; it won't let you overflow the buffer that is passed to it.

When we supply input, it wants the line to be of the form `[name_length]:[password_length]:[name][password]`. We can't supply more than 200 bytes to `read_str_until`; but we can set the size of both name and password buffers when parsed... maybe?

## Subi Subci

Not really sure about this AVR construct; there is a mix of places in the code where carry is handled in subtraction of immediates from 16bit variables stored in pairs of registers. Sometimes with a `subci -1` like below; sometimes not. I'm guess that the net effect is as I marked up in the comments but I can't convince myself that it is

```
movw    r22, YL
subi    r22, -0x1F
sbci    r23, -1         ; buffer = Y+0x1f
```

## `parse_and_maybe_set_flag_printer`

parse_and_maybe_set_flag_printer(input){
	input: Yx+0x4B
	first_colon: Yx+2
	saved_position: Yx+0x4A

	first_colon = strchr(input, ':') || return -1
	saved_position = 0


	saved_position ^= 1
	second_colon: Yx+4
	second_colon = strchr(first_colon + 1, ':') || return -1


	saved_position ^= 2
	next_dash: Yx+6
	next_dash = strchr(input, '-')


	if (!next_dash)
		next_dash > second_colon || return -1


	saved_position ^= 4
	first_colon_distance: Yx+8
	first_colon_distance = first_colon - input - 1
	weird_thing: Yx+0xA
	weird_thing = 0
	other_thing: Yx+0xC
	other_thing = first_colon
	first_colon_buffer = alloca(-(first_colon_distance + 1)) + 1
	first_colon_buffer: Y+0xE

	saved_position ^= 8
	distance_between_colons: Y+0x10
	distance_between_colons = second_colon - first_colon - 1
	high_test: r0
	high_test = (distance_between_colons & 0xff00) >> 8
	high_test = high_test << 1
	ya_weird_thing: Y+0x12
	ya_weird_thing = 0

	ya_distance_between_colons: Y+0x14
	ya_distance_between_colons = distance_between_colons
	second_colon_buffer = alloca(-(distance_between_colons + 1)) + 1
	second_colon_buffer: Y+0x16
	memcpy(first_colon_buffer, input, first_colon_distance)
	first_colon_buffer[first_colon_distance] = 0
	place_1: Y+0x28
	first_number: Y+0x1A
	after_1: Y+0x18
	first_number = strtoi(first_colon_buffer, place_1, 10)
	after_1=place_1

	saved_position ^= 16
	memcpy(second_colon_buffer, first_colon, distance_between_colons)
	second_colon_buffer[distance_between_colons] = 0
	second_number: Y+0x1E
	after_2: Y+0x1C
	second_number = strtoi(second_colon_buffer, place_1, 10)
	after_2 = place_1

	get_valid_rand(illegal_rand=saved_position)
	saved_position ^= 32
	before_second_digit_end = second_digit_end - 1
	later_buffer = alloca(-second_digit_end) + 1

	memcpy(name_field_buffer, input + first_colon_distance + distance_between_colons + 2, first_digit_end)

	if (saved_position != 0x3f)
		die_and_remember

	get_valid_rand(saved_position) // saved_position == 0x3f
	y = 100
	ret = 0
	while (y>0)
	{
		get_valid_rand(saved_position)
		saved_position = 0

		//mallocd_ptr: global
		rx24 = ( ((Y+saved_position)&0xff00 >> 8) + high_test) << 8 | high_test
		if (mallocd_ptr[rx24 + 32] == 0)
			continue



		...
		y--;
	}
	return ret
}

### stack layout
...
later_buffer = X - second_digit_end + 1

## `ROM:046D get_valid_rand`

This function is called by the `parse_and_maybe_set_flag_printer` function above. At this point I couldn't handle keeping track of `Y+NN` anymore so I wrote a stack-variable making script basing Y as the stack pointer (which avr-gcc appears to use).

 get_valid_rand(illegal_rand) {
 	word last_rand;
 	for (i=0; i<= 0xff; i++)
 		last_rand = prob_get_rand();
 	if (last_rand == illegal_rand) {
 		illegal_rand = last_rand;
 		for (i=0; i<0x400; i++) {
 			last_rand = prob_get_rand();
 		}
 		if (last_rand == illegal_rand)
 			die();
 	}
 	if (illegal_rand > 0x21 ) {
 		illegal_rand =- 0x30;
 		illegal_rand[H] = -1 * (illegal_rand[L] << 1 - illegal_rand[L] << 1);
 		illegal_rand[L] = illegal_rand[L] << 2;
 	}
 	illegal_rand_copy = illegal_rand;
 	j=0;
 	while(j < illegal_rand && illegal_rand_copy != 0) {
 		busy_mux();
 		j++;
 		busy_mux();
 		illegal_rand_copy--;
 	}
 	if (j != illegal_rand || illegal_rand_copy == 0)
 		die_and_remember();
 	busy_mux()
 	return illegal_rand_copy;
 }

# Back at it

Imported 6 or so functions from Jonathan's work in the other challenges

## `parse_and_maybe_set_flag_printer`

parse_and_maybe_set_flag_printer(input){
	input: Yx+0x4B
	first_colon: Yx+2
	saved_position: Yx+0x4A

	first_colon = strchr(input, ':') || return -1
	saved_position = 0


	saved_position ^= 1
	second_colon: Yx+4
	second_colon = strchr(first_colon + 1, ':') || return -1


	saved_position ^= 2
	next_dash: Yx+6
	next_dash = strchr(input, '-')


	if (!next_dash) {
		if (next_dash >= second_colon)
			return -1;
	}


	saved_position ^= 4
	first_colon_distance: Yx+8
	first_colon_distance = first_colon - input - 1
	weird_thing: Yx+0xA
	weird_thing = 0
	other_thing: Yx+0xC
	other_thing = first_colon
	first_colon_buffer = alloca(-(first_colon_distance + 1)) + 1
	first_colon_buffer: Y+0xE

	saved_position ^= 8
	distance_between_colons: Y+0x10
	distance_between_colons = second_colon - first_colon - 1
	high_test: r0
	high_test = (distance_between_colons & 0xff00) >> 8
	high_test = high_test << 1
	ya_weird_thing: Y+0x12
	ya_weird_thing = 0

	ya_distance_between_colons: Y+0x14
	ya_distance_between_colons = distance_between_colons
	second_colon_buffer = alloca(-(distance_between_colons + 1)) + 1
	second_colon_buffer: Y+0x16
	memcpy(first_colon_buffer, input, first_colon_distance)
	first_colon_buffer[first_colon_distance] = 0
	place_1: Y+0x28
	first_number: Y+0x1A
	after_1: Y+0x18
	first_number = strtoi(first_colon_buffer, place_1, 10)
	after_1=place_1

	saved_position ^= 16
	memcpy(second_colon_buffer, first_colon, distance_between_colons)
	second_colon_buffer[distance_between_colons] = 0
	second_number: Y+0x1E
	after_2: Y+0x1C
	second_number = strtoi(second_colon_buffer, place_1, 10)
	after_2 = place_1

	get_valid_rand(illegal_rand=saved_position)
	saved_position ^= 32
	before_second_digit_end = second_digit_end - 1
	later_buffer = alloca(-second_digit_end) + 1

	memcpy(name_field_buffer, input + first_colon_distance + distance_between_colons + 2, (uint16_t) first_digit_end)

	if (saved_position != 0x3f)
		die_and_remember

	get_valid_rand(saved_position) // saved_position == 0x3f
	y = 100
	ret = 0
	while (true)
	{
		if (y < 0) {
			return 2 ; badUser
		}

		get_valid_rand(saved_position);
		saved_position = 0;

		//mallocd_ptr: global
		if (mallocd_ptr[y * 34 + 32] == 0)
			continue;

		if ( (uint32_t) strlen(mallocd_prt[y * 34 + 32]) != (uint32_t) first_digit)
			continue;

		if ( !strncmp(mallocd_ptr[y * 34 + 32], name_field_buffer, (uint16_t) first_digit))
			continue;

		if ( saved_position != 0 )
			die_and_remember();

		get_valid_rand(saved_position);
		saved_position++;

		memcpy(later_buffer, input + first_colon_distance + distance_between_colons + first_digit + 2, second_digit);
		saved_position++;

		//hash: Y+42 (len == 32)
		prob_sha56_pbkdf(hash, later_buffer, work_factor = second_digit * 8);
		saved_position++;

		get_valid_rand(saved_position);
		if (saved_position == 3) {
			if( strncmp(mallocd_ptr[y * 34], hash, 32) ) {
				be_150_of_die_rng_artefact = 18 + 150;
			}
		}

		get_valid_rand(saved_position);
		saved_position++;
		get_valid_rand(saved_position);

		if (saved_position != 4)
			return 2; /badPassword;

		if( strncmp(mallocd_ptr[y * 34], hash, 32) ) {
			saved_position++;
			get_valid_rand(saved_position);
			if (saved_position != 5)
				die_and_remember();

			be_150_of_die_rng_artefact -= 18;

			fn_ptr_ptr_for247A = usart_send_byte_USARTC0;
		}

		y--;
	}
	return ret
}

## the function that initializes the mallocd_ptr

setup_100_structs_and_one_backdoor() {
	y == 100;
	while (y > 0) {
		mallocd_ptr + y*34 + 32 = 0
		mallocd_ptr + y*34 + 33 = 0
	}

	starts_at_99 = 99;

	memcpy(arg_0, copied_array, 32);

	memcpy(malloc_ptr + 99 * 34, arg_0, 32);

	mallocd_ptr + 99 * 34 + 32 = malloc(9);
	memcpy(mallocd_ptr + 99 * 34 + 32, 'backdoor', 9);

}

## Disassembly
```c
char copied_array[32] = {
	0x55, 0x03, 0x0C, 0x34, 0x9F, 0xC9, 0x5E, 0x13,
	0x85, 0x93, 0x5E, 0xA2, 0x33, 0x66, 0xB5, 0xA9,
	0x99, 0x45, 0xD8, 0xBF, 0x35, 0xD3, 0x72, 0xC3,
	0xAA, 0x72, 0x2B, 0xB9, 0x74, 0x92, 0xCA, 0x26
}

void setup_100_structs_and_one_backdoor(void) {
	char y1;        // Y+1
	char arg_0[32]; // Y+2..33 - end of frame

	starts_at_100 = 100;
	mallocd_ptr = malloc(starts_at_100 * 34);
	for (y1 = 0; y1 < starts_at_100; y1++) {
		Z = mallocd_ptr[y1 * 34];
		Z[32:33] = NULL;
	}
	starts_at_99 = 99;
	for (r24 = 32; r24 != 0; r24--) {
		arg_0[r24] = copied_array[r24];
	}
	for (r24 = 32; r24 != 0; r24--) {
		mallocd_ptr[starts_at_99*34 + r24] = arg_0[r24];
	}

	Z = mallocd_ptr[starts_at_99 * 34]
	Z[32:33] = malloc(9);
	for (r18 = 9; r18 != 0; r18--) {
		Z[32:33][r18] = "backdoor"[r18];
	}
}

char parse_and_maybe_set_flag_printer(char *input) {
	// stack frame 76
	char rop_check; // alias saved_position
	long first_digit; // "digit" is a misnomer, should be first number
	long second_digit; // "digit" is a misnomer, should be second number
	// input is shadowed at Y+0x4b..0x4c

	rx16 = $sp;
	first_colon = strchr(input, ':');
	if (first_colon == NULL) return -1;
	second_colon = strchr(first_colon, ':');
	if (second_colon == NULL) return -1;
	rx14 = $sp;
	next_dash = strchr(input, '-');
	if (next_dash != NULL && next_dash < second_colon) return -1;

	/* first block */ {
		first_colon_distance = first_colon - input;
		weird_thing = (first_colon_distance < 0); // length overflow test?
		other_thing = (short)((long)first_colon_distance + 1) - 1;
		first_colon_buffer = stack_alloc(first_colon_distance + 1);

		distance_between_colons = second_colon - first_colon - 1;
		// repeat of the BS above
		second_colon_buffer = stack_alloc(first_colon_distance + 1);

		memcpy(first_colon_buffer, input, first_colon_distance);
		first_colon_buffer[first_colon_distance] = '\0';
		first_digit = strtol(first_colon_buffer, &place_1, 10);

		memcpy(second_colon_buffer, first_colon, distance_between_colons);
		second_colon_buffer[distance_between_colons] = '\0';
		second_digit = strtol(second_colon_buffer, &place_1, 10);
	}
	// if (rop_check != 0x1f) die_and_remember();
	/* second block */ {
		second_digit_less_one = (short)second_digit - 1;
		later_buffer = stack_alloc( (short)second_digit );
		first_digit_less_one = (short)first_digit - 1;
		name_field_buffer = stack_alloc( (short)first_digit );

		memcpy(name_field_buffer, input[first_colon_distance + distance_between_colons + 2], (short)first_digit);
	}
	// if (rop_check != 0x3f) die_and_remember();

	for (y1 = starts_at_100; y1 > 0; y1--) {
		// rop_check = 0;
		Z = mallocd_ptr[y1 * 34];
		if (Z[32:33] == NULL) continue;
		if (first_digit != (long)strlen(Z[32:33])) continue;
		if (0 != strncmp(Z[32:33], name_field_buffer, first_digit)) continue;
		// if (rop_check != 0x0) die_and_remember();

		// rop_check += 1
		memcpy(later_buffer, input[first_colon_distance + distance_between_colons + 2 + first_digit], (short)second_digit);
		// rop_check += 1
		prob_sha256_pbkdf(hash, later_buffer, (long)second_digit*8);
		// rop_check += 1
		if (rop_check == 0x3 && 0 == strncmp(mallocd_ptr[y1*34], hash, 32)) {
			be_150_or_die_rng_artefact = 18+150;
		}
		// rop_check += 1
		// if (rop_check != 4) return 2; // bad password
		if (0 != strncmp(mallocd_ptr[y1*34], hash, 32)) return 2; // bad password
		// rop_check += 1
		// if (rop_check != 5) die_and_remember();
		be_150_or_die_rng_artefact -= 18;
		fn_ptr_ptr_for_247A = *usart_send_byte_USARTC0;
		return 1;
	}

	return 0; // unknown user
}

void main(void) {
	// stack frame: 231
	char y1[14];   // Y+0x1..0xe
	char y15[14];  // Y+0xf..0x1c
	char checks;   // Y+0x1d
	char mask;     // Y+0x1e
	char y1f[200]; // Y+0x1f..0xe6
	char result;   // Y+0xe7

	// bunch of init
	printf("Initializing...");
	// bunch of RNG tests
	printf("Initialized");
	setup_100_structs_and_one_backdoor();
	mask = 0;

	while (true) {
		read_str_until(y1f, 200);
		result = parse_and_maybe_set_flag_printer(y1f);
		if (result==1) {
			if (be_150_or_die_rng_artefact != 150) die();
			mask = 0xff;
			// if (checks!=7) die_and_remember();
			set_flag_mask(mask);
			// if (checks!=0xf) die_and_remember();
		}
		if (result==255) {
			printf("Expected format: [name_length]:[password_length]:[name][password");
		} else if (result==0) {
			printf("Unknown user!");
		} else if (result==2) {
			printf("Wrong password!");
		} else if (result==1) {
			if (be_150_or_die_rng_artefact != 150) die();
			printf("Your flag is:");
			// if (checks!=0x3f) die_and_remember();
			// if (checks!=0x3f) die_and_remember();
			// if (result!=1) die_and_remember();
			demask_and_print_flag();
			return 0;
		}
	}
}
```

## More Disassembly: crypto
```c
void prob_sha256_pbkdf(char *hash, char *buffer, long lenT8) {
	// stack frame 44
	char state[36];   // Y+0x01..0x24
	char *hash;    // Y+0x25..0x26
	char *buffer;  // Y+0x27..0x28
	long lenT8;    // Y+0x29..0x2c -- end of frame
	sha256_init_state(state); // h0, 0x00000000
	while (true) {
		erx24 = lenT8;
		if (lenT8 >= 0x200) { // length >= 64
			sub_b46(state, buffer);
			buffer += 0x40;
			lenT8 -= 0x200;
		} else {
			sub_ed3(state, lenT8);
			sub_1110(hash, state);
			return;
		}
	}
}
```

## Simulation
break:
	0x09f4: read_str_until
		- buffer at rx22 == 0x3f32,200
	0x184e: usart_print
		- buffer at rx22
	0x10c3: prob_sha256_pbkdf
		- below
	0x0810: in parse_and_maybe_set_flag_printer, delivery

Delays:
	time between "Initializing..." and "Initialized"
	too slow patching out:
	0x26da: cf93 -> 0895: jj_test_rng_rx24_times
	0x2b84: ff92 -> 0895: prob_more_rng_tests
	0x08da: cf93 -> 0895: get_valid_rand

## Transcript of exploitation:
```sh
ready and waiting...


Initializing...
Initialized
2018-04-30 10:04:05 -0400
prompt found, proceeding...
00000000  33 32 3a 33  37 33 34 3a  d9 fb 92 e3  bb e6 5b e1  │32:3│734:│····│··[·│
00000010  f1 aa d4 a8  2e ef 45 67  f7 a1 eb e2  cd 11 0c 80  │····│.·Eg│····│····│
00000020  49 b9 69 8b  e7 a7 0c 88                            │I·i·│····│
00000028


32:3734:......[.......Eg........I.i.....


Unknown user!
2018-04-30 10:04:21 -0400
00000000  38 3a 31 30  3a 62 61 63  6b 64 6f 6f  72 6f 70 65  │8:10│:bac│kdoo│rope│
00000010  6e 73 65 73  61 6d 65                               │nses│ame│
00000017
8:10:backdooropensesame


Your flag is:

18c495dbe625cd39544fc6e3bab81a2d
```

