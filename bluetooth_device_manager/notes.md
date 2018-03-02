
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
	* modify_stored_device_476() can kill null terminators on short strings
	* device_count_102194 is a char, will wrap early
	* connect_new_device_263() will copy some stack into device names/keys

Heap:
	* have multiple alloced elements A->B->C->D
	* and I delete an element (C)
	* then delete the previous one (B)
	* instead of merging with the B with C, it merges B with D
	* so B.size += D.size, not C.size
	* which means I can then malloc a new B, that overlaps on D.
	* which lets me overwrite the malloc header

## Analysis of `malloc`/`free`
	* malloc_break_10225D seems like the start of free space, mallocs will drop here unless they find a better place to do
	* I think malloc_freelist_10225F might be the free space list, made up of things that got free()d.
	* grabbed `malloc.c` from `apt source avr-libc`, it's a match.
		* `malloc()` ... exact match.
		* `free()` ...

## Todo
	* double check linked-list functions, look for a use-after-free
	* reverse free
	* check global usage patterns

## Exploitation
	* 

## Conditions for Victory
	* must invoke `print_flag_182()`
	* it will compare `RAM:0x2000 == 0xF00D` to clear flag_mask_102210
	* it will compare `RAM:0x2002 == 0xBAAD` to print_flag_sub()
	* but, if `stack_102192 < Y+1` it will complain about pivoting and bail.

## Decompilation of normal functions
Fred

```c
short broken_read_str_until_13b(void* usart, char* buffer, short length, char terminator) {
	short i;       // Y+1..2
	char c;        // Y+3
	// p usart is at  Y+4..5
	// p buffer is at Y+6..7
	// p length is at Y+8..9
	// p term   is at Y+0xa
    for (i = 0; i < length; i++) {
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

	if (device == NULL && prev_out != NULL) {
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
	Entry *X;
	Entry *Y;
	Entry *Z;

	if (length <2) length = 2;
	Entry *Z = malloc_freelist_10225F;
	Entry *prevEntry = NULL; // Y
	Entry *bestEntry;        // X
	Entry *bestPrevEntry;    // rx22
	short bestEntrySize = 0; // rx18

	for ( ; Z!=NULL; prevIter = freeIter, freeIter = freeIter.next) {
		if (Z.length < length) continue;

		if (Z.length == length) {
			// exact hit, use it.
			if (prevEntry == NULL) {
				malloc_freelist_10225F = Z.next
			} else {
				prevEntry.next = Z.next
			}
			return &Z.body;

		} else if ((bestEntrySize == 0 || Z.length < bestEntrySize)) {
			bestEntrySize = Z.length;
			bestPrevEntry = prevEntry;
			bestEntry = Z;
		}
	}

	if (bestEntrySize == 0) {
		// no place to put it, append.
		if (malloc_break_10225D == NULL) {
			malloc_break_10225D = malloc_heap_start_102016; // RAM:0x2261
		}
		void* end = malloc_heap_start_102014;
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

	Entry *freeIter = malloc_freelist_10225F; // X
	Entry *prevIter = NULL;                   // rx20
	for ( ; freeIter != NULL; prevIter = freeIter, freeIter = freeIter.next) {
		if (freeIter < entry) continue;

		// we've found or passed the entry
		entry.next = freeIter;
		X = prevIter;
		Entry *nextEntry = ptr + entry.length; // rx24

		if (nextEntry != freeIter) {
			entry.length += nextEntry.length + 2;
				// XXX should be freeIter, not nextEntry
			entry.next = nextEntry.next;
				// XXX should be freeIter, not nextEntry
		}

		if (prevIter == NULL) {
			malloc_freelist_10225F = entry;
			return;
		} else {
			break;
		}

	}

	// loc_138e
	prevIter.next = entry;
	if (entry == prevIter + 2 + prevIter.length) {
		prevIter.length += entry.length + 2;
		prevIter.next = entry.next;
	}

	freeIter = malloc_freelist_10225F; // rx16, also X
	prevIter = NULL;                   // Z
	while ( freeIter.next != NULL) {
		prevIter = freeIter;
		freeIter = freeIter.next;
	}

	if (malloc_break_10225D == &(freeIter.next) + freeIter.length) {
		if (entry == NULL) {
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

