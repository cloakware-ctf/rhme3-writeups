
## Challenge
You have a basic car model and would like to enable some extra features? That navigation with traffic should be neat. Right. It is expensive, you know. Or not, if you can access the control interface. Try bluetooth this time. We think, it could be used for purposes other than making calls and playing MP3s.

## Initial Analysis
Loop 1: X <- Z
	X = 0x2000 .. 0x2190
	Z = 0x2dd0
Loop 2: X <- 0
	X = 0x2190 .. 0x2261

Hmmmmmm.... strcpy.... strlen... this will be fun.
Bindiff picked up 39 / 97 functions. That's a really good start.

## Ways this Program is Broken
Main program:
	* broken_read_str_until_13b() doesn't always null terminate strings it reads
	* print_all_connected_devices_3eb() doesn't limit print length, might dump heap
	* "such heap" -> heap attacks
	* modify_stored_device_476() can kill null terminators on short strings -> heap reads
	* device_count_102194 is a char, will wrap early
	* connect_new_device_263() will copy some stack into device names/keys, but can't print

Missing Vuln:
	* I need another flaw, possibles:
		* use-after-free
		* type-confusion
		* off-by-one errors

Heap:
	* have multiple alloced elements A->B->C->D
	* and I delete an element (C)
	* then delete the previous one (B)
	* instead of merging with the B with C, it merges B with D
	* so B.size += D.size, not C.size
	* which means I can then malloc a new B, that overlaps on D.
	* which lets me overwrite the malloc header
	* or alternately, it means that previous string content is now a freelist node

## Analysis of `malloc`/`free`
	* malloc_break_10225D seems like the start of free space, mallocs will drop here unless they find a better place to do
	* I think malloc_freelist_10225F might be the free space list, made up of things that got free()d.
	* grabbed `malloc.c` from `apt source avr-libc`, it's a match.
		* `malloc()` ... exact match.
		* `free()` ... not quite, there's a bug in freelist chunk aggregation
		* nope, I was wrong. The code is correct.

## Todo
	* double check linked-list functions, look for a use-after-free
	* check global usage patterns

## Simulations
	* check how the stack init process works, make sure stack_102192 is set where I expect
	* random jump into print_flag_182 and check how pivot defense works

Breakpoints:
	* print_flag_182
	* serial_printf_774
		* prefer to break at 0x78d, and look in 0x2195
	* broken_read_str_until_13B
		* buffer is at rx22 / Y[6:7]

	1. print_all_connected_devices_3EB
	2. connect_new_device_263
		* buffer is at 0x3d14 .. 0x3ddb
		* first malloc at 0x2269
		* and Y was pushed on the stack right before we did anything
			-> so when we over-read, we get 0x3fd4, which is the stack frame in main
			-> useless
		* first string body at 0x2276, length 202
		* second string body at 0x2343, length 11
	3. disconnect_device_35C
		* note: 0-based.
		* after execution
	4. modify_stored_device_476

	* malloc_12a8

Results:
	* stack_102192 points to RAM:0x3de1, which is the first non-null byte over the jump
	* the bytes immediately above that are the return address in main
	* we don't have a guaranteed stack infoleak, might have to rely on the 1/11 chance.
	* we filling gaps, we alloc in reverse order
	* STATE: ve a, delete(b), c. Need to alloc 3. Then: [0, 3, 2, 4, 5], delete 4 then 3.

## Exploitation
### ideas
	1. Create a bogus heap chain inside a string body.
	2. (and two wrapper entries)
	3. delete the target entry
	4. now malloc a new entry
	5. it will use my chosen locations on stack and heap for name and key
	6. so name will overwrite DEADBEEF, key will overwrite return address
	7. flag.

Let's look for way to abuse a malformed heap:
	* `free()` is not promising
		- maybe I can make it think that prevIter is RAM:0x2000, and it needs to coalesce with my chosen element.
		- that would allow me to arbitrarily set four bytes of it.
		- to do that, I'd need to put a node at RAM:0xBEEF ... which might be possible, but stack is usually at 0x4000...
		- assuming best case: 0xbeef is off ram, and returns 0, nothing good comes
	* if I can screw with the `brk`, I could set that to RAM:0x1ffe and alloc 4 bytes (then modify to baadf00d)
	* if I create a freelist entry with a crazy size, and it's the "best match",

Pivoting:
	* I don't understand how the pivot defense works, I'm not going to set $sp to the high-stack gap.
	*

### Stack infoleak
	* the printf buffer is only 120 characters long, so if I fill the connect_new_device_263 buffer, I still don't get to see the next bytes
	* but they are on the heap, if I need them
	* the //if// is there, because what I get is 0x3fd4, which is ``main_546``'s stack frame pointer, which doesn't seem super valuable
	* Now, there's 46 populated bytes in the random gap, so roughly 1/11 times the leak will tell me where the stack pointer is.

### Heap infoleak
	* possible, an easy way is to:
		1. alloc 5 chunks (a,b,c,d,e),
		2. free b and e
		3. modify a to determinate key
		4. print out a
		* constraints: b's total size needs to be >255; a needs to be small enough to fit in print_buffer
	* HOWEVER: the stack is 100% predictable, no need to infoleak it.

### Write-What-Where
	* 

### Control $PC
	* only thing I can think of is RET
	* also ICALL, EICALL, only in fputc, and print_flag
	* CPU_EIND, unused.
	* use WWW to munch a return address

## Exploitation -- Take 2
Situation: we can write one byte into the heap. This one byte controls the size of the alloc/freelist entry we write into.

What can we do with this?
	1. create devices A,B,C,D
	2. delete B
	3. modify A to extend B to include C
	4. create devices D,E in extended B, where E is contained in C
	5. delete D
State:
	* one part of C contains D, which is a freelist node, and we can write it.

Plan: Stack Infoleak
	1. collide two malloc entries
    2. modify the `name` of one using the other (where)
	3. print the one... seeing what's there.

Plan: Write What Where
	1. collide two malloc entries
	2. modify the `name`, `nameLen` of one using the other (where)
	3. modify the one writing arbitrary data to `name` (what)

Plan: Goals
	1. 0xBAADF00D to 0x2000
	2. 0x000182 to `modify_stored_device_476()`'s return address

Plan: Details
	* see heap-pro.rb
	* key insight: I can reference stack_102192 to get the slide
	* it works now, but complains about the pivot...
	* to fix: I'm using the return to main, I need to use the return to modify_stored_device_476 from broken_read_str_until_13B
	* RAM:0x2000: DA, DE, 3F B3 -> 0D, F0, AD, BA
	* holy hell, I had them inverted. I was setting 0xBAADF00D, when I needed 0xF00DBAAD
```
such heap, much pr0!
Your flag: 34ab43567e396c842d9e6c99a08723dc
```

## Conditions for Victory
	* must invoke `print_flag_182()`
	* it will compare `RAM:0x2000 == 0xF00D` to clear flag_mask_102210
	* it will compare `RAM:0x2002 == 0xBAAD` to print_flag_sub()
	* but, if `stack_102192 < Y+1` it will complain about pivoting and bail.
		* note: heap ranges from RAM:0x2261 .. $sp-0x20
		* stack ranges from $sp to 0x3FFF
		* stack

	0x0 memory mapped io
	0x2000 .data
	0x2261 .bss / heap
	0x3d05 Y+1
	0x3d?? stack values
	0x3e0c stack_102192
	0x3FFF end of stack

Known Locations:
	0x2192: stack_102192
	0x2194: device_count_102194
	0x2195: print buffer

## Decompilation of normal functions
```c
short broken_read_str_until_13b(void* usart, char* buffer, short length, char terminator) {
	short i;       // Y+1..2
	char c;        // Y+3
	// p usart is at  Y+4..5
	// p buffer is at Y+6..7
	// p length is at Y+8..9
	// p term   is at Y+0xa
    for (i = 0; i <= length; i++) { // XXX DEFECT: off-by-one error
		c = usart_recv_byte(usart);
		j_usart_send_byte(usart, c);
		buffer[i] = c;
		if (c == terminator) {
	   	buffer[i] = '\0'; // XXX DEFECT: only done if newline, not if i>=length
			break;
		}
	}
	return i;
}

void device_list_append_225(DeviceLink *device) {
	// pp_device is at Y+1..2
	if (*device_list_102190 == NULL) {
		device_list_102190.head = device;
		device_list_102190.tail = device;
	} else {
		device_list_102190.tail.next = device;
		device_list_102190.tail = device
	}
}

DeviceLink *device_list_find_319(char id, DeviceLink **prev_out) {
	DeviceLink *prev;   // Y+1..2
	DeviceLink *device; // Y+3..4
	// id is at            Y+5
	// prev_out is at      Y+6..7

	prev = NULL;
	device = device_list_102190.head;
	while (device != NULL) {
		if (device.id == id) break;
		prev = device;
		device = device.next;
	}

	if (device != NULL && prev_out != NULL) {
		*prev_out = prev;
	}

	return device;
}

struct DeviceList = {
	DeviceLink *head; // Z[0:1]
	DeviceLink *tail; // Z[2:3]
};

struct DeviceLink = {
	uint8_t id;       // Z
	short nameLen;    // Z[1:2]
	short keyLen;     // Z[3:4]
	char *name;       // Z[5:6]
	char *key;        // Z[7:8]
	DeviceLink *next; // Z[9:A]
};
```

```c
void print_all_connected_devices_3eb(void) {
	DeviceLink *device; // Y+1..2

	device = device_list_102190.head;
	while (device != NULL) {
		serial_printf("%d. name: %s, key: %s", device.id, device.name, device.key);
		device = device.next;
	}
}

void connect_new_device_263(void) {
	DeviceLink *device;
	char buffer[200]; // Y+3..+202

	device = malloc( sizeof(DeviceLink) );
	memset(device, 0,  sizeof(DeviceLink) );

	serial_printf("Enter device name: ");
	broken_read_str_until_13b(USARTC0_DATA, buffer, 200, '\n');
	device.nameLen = strlen(buffer)+1;
	device.name = malloc( device.nameLen );
	strcpy(device.name, buffer);

	serial_printf("Enter pairing key: ");
	broken_read_str_until_13b(USARTC0_DATA, buffer, 200, '\n');
	device.keyLen = strlen(buffer)+1;
	device.key = malloc( device.keyLen );
	strcpy(device.key, buffer);

	device.id = device_count_102194;
	device_count_102194 += 1;
	device.next = NULL;

	device_list_append_225(device);
}

void disconnect_device_35c(char id) {
	DeviceLink *device; // Y+1..2
	DeviceLink *prev;   // Y+3..4
	// id is at            Y+5

	device = device_list_find_319(id, &prev);
	if (device != NULL) {

		if (prev != NULL) {
			prev.next = device.next
		}
		if (device_list_102190.head == device) {
			device_list_102190.head = device.next
		}
		if (device_list_102190.tail == device) {
			if (prev == NULL) {
				device_list_102190.tail = device_list_102190.head
			} else {
				device_list_102190.tail = prev;
			}
		}
		free(device.name);
		free(device.key);
		free(device);

	} else {
		serial_printf("Error: Could not find device with this id!");
	}
}

void modify_stored_device_476(char id) {
	short y1;           // Y+1..2
	DeviceLink *device; // Y+3..4
	// id is at            Y+10
	// stack 10

	y1 = 1; // XXX why 1?
	device = device_list_find_319(id, 0);

	if (device != NULL) {
		serial_printf("%d. %s, %s", y1, device.name, device.key);

        serial_printf("Enter new name: ");
		broken_read_str_until_13b(USARTC0_DATA, device.name, device.nameLen, '\n');
		// XXX super interesting

        serial_printf("Enter new key: ");
		broken_read_str_until_13b(USARTC0_DATA, device.key, device.keyLen, '\n');
		// XXX super interesting
	} else {
		serial_printf("Error: Could not find device with this id!");
	}
}

void cleanup_439(void) {
	DeviceLink *device; // Y+1..2
	short y3 = 1;       // Y+3..4
	DeviceLink *swap;   // Y+5..6

	device = device_list_102190.head;
	while (device != NULL) {
		swap = device;
		device = device.next
		free(swap.name);
		free(swap.key);
		free(swap);
	}
}

int main_546() {
	short y1;    // Y+1..2
	short y3;    // Y+3..4
	short y5;    // Y+5..6
	char input[32]; // Y+7..38

	y1 = random_word() &0x1ff; // %512
	y3 = y1 -1;
	$sp -= y1;
	y5 = $sp+1;
	stack_102192 = y5;
	init_clock();
	config_usart_681(USARTC0);
	{
		device_list_102190 = malloc(sizeof(DeviceList));
		memset(device_list_102190, 0, sizeof(DeviceList));
	}

	while (true) {
		serial_printf("Choose one of the following: ");
		serial_printf("1. Print all connected devices");
		serial_printf("2. Connect new device");
		serial_printf("3. Disconnect device");
		serial_printf("4. Modify stored device");
		serial_printf("5. Exit");
		broken_read_str_until_13b(USARTC0_DATA, input, 16, '\n');
		switch (atoi(input)) {
			case 1:
				print_all_connected_devices_3eb();
				break;
			case 2:
				connect_new_device_263();
				break;
			case 3:
				serial_printf("Enter number of device: ");
				broken_read_str_until_13b(USARTC0_DATA, input, 16, '\n');
				disconnect_device_35c( atoi(input) );
				break;
			case 4:
				serial_printf("Enter number of device: ");
				broken_read_str_until_13b(USARTC0_DATA, input, 16, '\n');
				modify_stored_device_476( atoi(input) );
				break;
			case 5:
				cleanup_439();
				die(1);
			default:
				serial_printf("\n");
				break;
		}
	}
}
```

## Decompilation of Heap Functions
```c
struct Entry {
	short length;
	union {
		Entry *next;
		void *body;
	}
}

void *malloc(short length) {
	if (length <2) length = 2;

	Entry *freeIter = malloc_freelist_10225F; // Z
	Entry *prevEntry = NULL; // Y
	Entry *bestEntry;        // X
	Entry *bestPrevEntry;    // rx22
	short bestEntrySize = 0; // rx18

	/*
	 * First, walk the free list and try finding a chunk that
	 * would match exactly.  If we found one, we are done.  While
	 * walking, note down the smallest chunk we found that would
	 * still fit the request -- we need it for step 2.
	 */
	for ( ; freeIter!=NULL; prevIter = freeIter, freeIter = freeIter.next) {
		if (freeIter.length < length) continue;

		if (freeIter.length == length) {
			// exact hit, use it.
			if (prevEntry == NULL) {
				malloc_freelist_10225F = freeIter.next;
			} else {
				prevEntry.next = freeIter.next;
			}
			return &freeIter.body;

		} else if ((bestEntrySize == 0 || freeIter.length < bestEntrySize)) {
			bestEntrySize = freeIter.length;
			bestPrevEntry = prevEntry;
			bestEntry = freeIter;
		}
	}

	/*
	 * Step 3: If the request could not be satisfied from a
	 * freelist entry, just prepare a new chunk.  This means we
	 * need to obtain more memory first.  The largest address just
	 * not allocated so far is remembered in the brkval variable.
	 * Under Unix, the "break value" was the end of the data
	 * segment as dynamically requested from the operating system.
	 * Since we don't have an operating system, just make sure
	 * that we don't collide with the stack.
	 */
	if (bestEntrySize == 0) {
		// no place to put it, append.
		if (malloc_break_10225D == NULL) {
			malloc_break_10225D = malloc_heap_start_102016; // RAM:0x2261
		}
		void* end = malloc_heap_end_102014;
		if (end == NULL) { // always is? possibly different in live load
			end = $sp - malloc_margin_102018; // 0x0020 -- tiny...
		}
		Entry *brk = malloc_break_10225D;
		if (brk >= end) {
			return NULL; // out of memory
		}
		short avail = end - brk;
		if (avail <= length || avail <= length + 2) {
			return NULL; // out of memory
		}
		malloc_break_10225D += length + 2;
		nextAlloc.length = length;
		return &nextAlloc.body;

	/*
	 * Step 2: If we found a chunk on the freelist that would fit
	 * (but was too large), look it up again and use it, since it
	 * is our closest match now.  Since the freelist entry needs
	 * to be split into two entries then, watch out that the
	 * difference between the requested size and the size of the
	 * chunk found is large enough for another freelist entry; if
	 * not, just enlarge the request size to what we have found,
	 * and use the entire chunk.
	 */
	} else {
		// no perfect fit, use closest match
		short deltaSize = bestEntrySize - length;
		if (deltaSize >= 4) {
			// new entry in the space
			Z = bestEntry + deltaSize;
			Z.length = length;
			bestEntry.length = deltaSize - 2;
			return &Z.next;
		} else {
			// resize element to fill space
			if (bestPrevEntry == NULL) {
				malloc_freelist_10225F = bestEntry.next;
			} else {
				bestPrevEntry.next = bestEntry.next;
			}
			return &bestEntry.next;
		}
	}
}

void free(void *ptr) {
	if (ptr == NULL) return;

	Entry *entry = ptr-2; // Z
	entry.body = 0;
	if (malloc_freelist_10225F == NULL) {
		if (malloc_break_10225D == ptr + entry.length) {
			// free of last element, just subtract from end
			malloc_break_10225D = entry;
		} else {
			// create freed list
			malloc_freelist_10225F = entry;
		}
		return;
	}

	/*
	 * Now, find the position where our new entry belongs onto the
	 * freelist.  Try to aggregate the chunk with adjacent chunks
	 * if possible.
	 */
	Entry *freeIter = malloc_freelist_10225F; // X
	Entry *prevIter = NULL;                   // rx20
	for ( ; freeIter != NULL; prevIter = freeIter, freeIter = freeIter.next) {
		if (freeIter < entry) continue;

		// we've found or passed the entry
		entry.next = freeIter;
		X = prevIter;
		Entry *nextEntry = ptr + entry.length; // rx24

		if (nextEntry == freeIter) {
			entry.length += nextEntry.length + 2;
			entry.next = nextEntry.next;
		}

		if (prevIter == NULL) {
			malloc_freelist_10225F = entry;
			return;
		} else {
			break;
		}

	}

	// FACTS:
	// freeIter is NULL or freeIter >= entry
	// note: $sp is >= entry
	// prevIter is < entry (or is NULL, but unlikely)
	//

	/*
	 * Note that we get here either if we hit the "break" above,
	 * or if we fell off the end of the loop.  The latter means
	 * we've got a new topmost chunk.  Either way, try aggregating
	 * with the lower chunk if possible.
	 */
	prevIter.next = entry;
	if (entry == prevIter + 2 + prevIter.length) {
		prevIter.length += entry.length + 2;
		prevIter.next = entry.next;
	}

	/*
	 * If there's a new topmost chunk, lower __brkval instead.
	 */
	freeIter = malloc_freelist_10225F; // rx16, also X
	prevIter = NULL;                   // Z
	while ( freeIter.next != NULL) {
		prevIter = freeIter;
		freeIter = freeIter.next;
	}

	if (malloc_break_10225D == &(freeIter.next) + freeIter.length) {
		if (prevIter == NULL) {
			malloc_freelist_10225F = 0;
		} else {
			prevIter.next = 0;
		}
		malloc_break_10225D = freeIter;
		return;
	} else {
		return;
	}
}

```

