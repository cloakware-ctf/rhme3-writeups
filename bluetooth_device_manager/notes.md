
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
	* broken_read_str_until_13b() doesn't always null terminate strings it reads
	* print_all_connected_devices_3eb() doesn't limit print length, might dump heap
	* "such heap" -> heap attacks
	* modify_stored_device_476() can kill null terminators on short strings
	* device_count_102194 is a char, will wrap early
	* connect_new_device_263() will copy some stack into device names/keys

## Analysis of `malloc`/`free`
	* malloc_word_10225D seems like the start of free space, mallocs will drop here unless they find a better place to do
	* I think malloc_entries_10225F might be the free space list, made up of things that got free()d.


## Conditions for Victory
	* must invoke `print_flag_182()`
	* it will compare `RAM:0x2000 == 0xF00D` to clear flag_mask_102210
	* it will compare `RAM:0x2002 == 0xBAAD` to print_flag_sub()
	* but, if `stack_102192 < Y+1` it will complain about pivoting and bail.

## Decompilation of normal functions
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
			buffer[i] = '\0'; // XXX DEFECT only done if newline, not if i>=length
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
	short unk23;
}

void *malloc(short length) {
	Entry *X;
	Entry *Y;
	Entry *Z;

	if (length <2) length = 2;
	Z = malloc_entries_10225F;
	Y = NULL;
	rx18 = 0;
	while (true) {
		if (Z == NULL && rx18 == 0) {
			if (malloc_word_10225D == NULL) {
				malloc_word_10225D = p_bss_start_102016; // RAM:0x2261
			}
			rx18 = word_102014;
			if (rx18 == NULL) { // always is? possibly different in live load
				rx18 = $sp - off_102018; // 0x0020
			}
			Z = malloc_word_10225D;
			if (Z >= rx18) {
				return NULL; // out of memory
			}
			rx18 -= Z;
			if (rx18 <= length) {
				return NULL; // out of memory
			}
			rx20 = rx24 + 2;
			if (rx18 <= rx20) {
				return NULL; // out of memory
			}
			rx20 += Z;
			malloc_word_10225D = rx20;
			Z.length = length;
			return Z+2;
		}
		if (Z == NULL && rx18 != 0) {
			rx18 -= length;
			if (rx18 >= 4) {
				Z = X + rx18;
				Z.length = length;
				rx18 -= 2;
				X.length = rx18;
				return Z+2;
			} else {
				X += 2;
				length = X.length
				X -= 2;
				if (rx22 == 0) {
					malloc_entries_10225F = length;
				} else {
					Z = rx22;
					Z.unk23 =  length;
					Z = X;
				}
				return Z+2;
			}
		}
		if (Z != NULL && Z.length == length) {
			if (Y == 0) {
				malloc_entries_10225F = Z.unk23
			} else {
				Y.unk23 = Z.unk23
			}
			return Z+2;
		}
		if (Z != NULL && Z.length > length) {
			if (rx18 == 0 || rx20 < rx18) {
				rx18 = rx20;
				rx22 = Y;
				X = Z;
			}
			Y = Z;
			Z = Z.unk23;
			continue;
		}
		if (Z !=  NULL && Z.length < length) {
			Y = Z;
			Z = Z.unk23;
			continue;
		}
	}
}

void free(void *ptr) {
	Entry Z;

	if (ptr == NULL) return;
	Z = ptr-2;
	Z.unk23 = 0;
	rx16 = malloc_entries_10225F;
	if (rx16 == 0) {
		ptr += Z.length
		rx18 = malloc_word_10225D
		if (malloc_word_10225D == 0) {
			malloc_word_10225D = Z;
		} else {
			malloc_entries_10225F = Z;
		}
		return;
	}

	X = rx16;
	rx20 = 0;
	while (true) {
		if (X >= Z) {
			rx18 = X;
			X = rx20;
			Z.unk23 = rx18;
			rx22 = Z.length;
			ptr += Z.length;
			if (ptr != rx18) {
				Y = ptr;
				rx18 = Y.length + rx22 + 2;
				Z.length = rx18;
				ptr = Y.unk23;
				Z.unk23 = ptr;
			}
			if (rx20 == 0) {
				malloc_entries_10225F = Z;
				return;
			} else {
				break;
			}
		} else {
			rx18 = X.unk23;
			rx20 = X;
			if (rx18 == NULL) {
				break;
			} else {
				X = rx18;
				continue;
			}
		}
	}

	// loc_138e
	X.unk23 = Z
	Y = X;
	rx20 = Y.length;
	Y+= 2;
	rx18 = Y + rx20
	if (Z == rx18) {
		ptr = Z.length + rx20 + 2;
		X.length = ptr;
		ptr = Z.unk23;
		X.unk23 = ptr;
	}
	Z = NULL;
	while (true) {
		X = rx16;
		ptr = X.unk23;
		if (ptr == NULL) break;
		Z = rx16;
		rx16 = ptr;
	}

	ptr = X.length
	rx18 = rx16 + 2;
	ptr += rx18;
	rx18 =  malloc_word_10225D;
	if (rx18 == ptr) {
		if (Z == NULL) {
			malloc_entries_10225F = 0;
		} else {
			Z.unk23 = 0;
		}
		malloc_word_10225D = rx16;
		return;
	} else {
		return;
	}
}

```

