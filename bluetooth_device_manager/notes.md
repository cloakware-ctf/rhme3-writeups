
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

## Conditions for Victory
	* must invoke `print_flag_182()`
	* it will compare `RAM:0x2000 == 0xF00D` to clear flag_mask_102210
	* it will compare `RAM:0x2002 == 0xBAAD` to print_flag_sub()
	* but, if `stack_102192 < Y+1` it will complain about pivoting and bail.

## Decompilation
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
			buffer[i] = '\0'; // XXX DEFECT
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
	DeviceLink *head;
	DeviceLink *tail;
};

struct DeviceLink = {
	uint8_t id;       // Z
	short nameLen;    // Z[1:2]
	short keyLen;     // Z[3:4]
	char *name;       // Z[5:6]
	char *key;        // Z[7:8]
	DeviceLink *next; // Z[9:A]
};

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
			free(device.name);
			free(device.key);
			free(device);
		}

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

int main() {
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


