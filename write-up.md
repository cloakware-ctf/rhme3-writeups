
## Categories
### Reverse Engineering
 50 Ransom
150 Ransom 2.0
250 Full Compromise
500 Car Crash

### Exploitation
100 Unauthorized
200 Bluetooth Device Manager
750 Climate Controller Catastrophe

### CAN Bus
150 Can Opener
250 Back To The Future
500 Auto-psy

### Side Channel Analysis
200 It's A Kind Of Magic
350 The Imposters
500 Random Random Everywhere

### Fault Injection
300 The Lockdown
500 Benzinegate

### ¯\_(ツ)_/¯
100 Race Of A Lifetime
100 Phonic Frenzy 1
200 Phonic Frenzy 2
500 Car Key Fob Hardware Backdoor

## Reverse Engineering
[How to use the IDA scripts](atxmega128a4u/scripts/README.md)

TODO: general description

### Simulation
We simulated many of the provided .hex files using Atmel Studio. The simulator can't use .hex files, only .elf files, but it has a utility that can convert .hex files into .elf files. Here's the steps:
  1. Tools -> Device Programming -> Simulator / ATxmega128A4U
  2. Production file, Save to ELF production file, Flash: <target>.hex
  3. Tick the Flash box
  4. Save

And then to actually simulate:
  1. File -> Open -> Open Object File for Debugging
  2. Select the Object File To Debug: <target>.elf

The simulator is awful. Useful notes:
  * You can type in equations into the "jump to program address" bar at the top. If you want to check out sub_632, type in `2*0x632`, that'll put you where you want to be.
  * Similarly, type equations into the watch window. You'll often want ones like `r24+256*r25`
  * You can modify program memory in appropriate pane, but it's often easier to patch the .hex file using IDA or the .elf file using r2.
  * When searching for help, know that Atmel Studio is a modified version of Visual Studio, so the resources for the latter often apply.
  * The simulator is _WAY SLOWER_ than the actual board. I'm estimating a factor like x10000. Serious. Many challenges incorporate anti-FI checks and anti-RNG-pinning checks that will take literally hours in the simulator. Patch them out before you start.
  * Serial I/O just doesn't work. Set a breakpoint on print functions and a watch on the place the string will show up.
  * For input functions, break just before entry and manually key the desired string into the buffer the function will populate.


### Ransom and Ransom 2.0
[Detailed Notes](ransom/notes.md)

This is the most straightforward reverse engineering challenge. Our RE framework wasn't very solid at this point, so the notes aren't as detailed as later challenges. We defeated primarily by simulation. The challenge takes a userid (that the board will print out on serial), and derives an unlock code from it. The .hex file we're provided doesn't have the userid included, so we waited until it read it out from EEPROM, and overwrote it with the code the board printed out.

Continuing the simulation, we captured the 16 byte stream the program derived from the userid, and used that as the unlock code.

Note: The first version of the challenge had a bug in it where it would only check the first digit of the provided unlock code. Trivial brute-force would defeat that.

### Full Compromise
[Detailed Notes](full_compromise/notes.md)

This challenge is a pig, and there's no way it's only worth 250 points. Reading the binary, there's a couple obvious "hidden" functions in the main input parsing loop. First, instead of running a "test", we can run a "risc". There's no reason to do so. Maybe the infoleak described below was only supposed to be present in "risc" runs, who knows? Second, if you type a '*', you get put into a funny mode, that leads eventually to the `flag_4d15()` function.

How do we navigate that path? Well, let me tell you...

In reverse order:
  1. We need to have submitted the right code. We can easily get the right code by simulating the `init_hash_102acf_4709()`, and checking what got put there. (Notation note: that function will `init` a global variable named `hash_102acf`, and the function's hex address is `0x4709`.)
  2. The password we submit is "processed" by a function `process_password_47cc()`. Which is just a busy wait with a counter of 500,000,000. Truth. That BS takes about six hours to loop. Apparently someone was a _little_ concerned about bruteforcing. (A 250 **byte** long fully random password, WTF)
  3. And we have to enter that password using pulse dialing. It doesn't matter what character we send (other than '*'), what matters is the delay since the last character. If you want the first character to be 0xa5, then send 165 characters, then wait ~6 seconds for the character to be accepted. Dialing at this speed, it takes about a half-hour just to clock the passcode in. (Fortunately, the board echos out the password it received, so you can check for errors).
  4. As if that wasn't enough, there are 1000 binaries. You need to figure out which passcode to use...

How to figure out which binary? That's where the 'test' command comes in. This function bigbangs the contents of a pair of arrays out through the DAC. However, those two arrays are constant across all binaries. Further examination shows that of the 100 entries 10 are modified slightly by a random slice of an array called `randombits_102a6b[]`. That array's contents vary per-binary. Here's what we did:
  1. Programmatically run the "test" command 200 times, capture the results with a scope, and export the scope results to .csv files. (We did this using [AutoHotkey](https://autohotkey.com/))
  2. Use a script to extract 10 bit sequences from the analogue scope results
  3. Use another script to collate them into a 110 bit long sequence
  4. Use [simavr](https://github.com/buserror/simavr) to simulate the function that generates the "randombit" arrays, for all 1000 binaries.
  5. Find out which one matches the string we got from the board.

Ok, that's all in place now, all that's left is to simulate the correct binary, find out the code, pulse-dial it into the board, wait six hours, and use `stdbuf -o0` so that we actually get to see the flag.

An easy 250 points. (lol wtf!)

### Car Crash
[Detailed Notes](car_crash/notes.md)

We have a simple command interface. Using it, we can print out the encrypted logs, and we can "decrypt" and print the "decrypted" logs. Only problem is, the "decrypted" logs are garbage.

Reversing quickly showed the existence of an unreferenced pair for the "decryption" function, meaning that the binary contains both encrypt and decrypt. I didn't recognize the algorithm, so I converted the disassembly into C, wrote a wrapper for it, and fixed it up so it built and ran. [Source](car_crash/crash.cc).

It didn't quite work at first, so I fired up the simulator, my code in gdb, and ran the two side-by-side and fixed my code to match the simulator. I did the same for the unused crypto function, by just moving $pc in the simulator. Once I had an identically working copy in C, I reverse that instead of the AVR code.

Using a known plaintext, I reduced the algorithm to a single round, and printed all intermediates. I saw that in a round-trip, my plaintext->ciphertext->plaintext sequence diverged after the sbox step of decryption. Then I saw that some entries in the `inverse_sbox_102110[]` had been zeroed. Fixing that is trivial given the forward sbox, and immediately produced a clear decrypt of the logs.

## Exploitation
See Reversing Engineering above for details. We followed the same procedure here.

### Unauthorized
[Detailed Notes](unauthorized/notes.md)

Initial reverse engineering showed the existence of a 'backdoor' account, with a 32 byte password hash. Just in case, we threw hashcat at it, but got no results.

Working backward from the flag printing function, the code searches through the list of configured users, if it finds a match, checks that the hash of the password matches the hash in the list using `strncmp()`, and if so prints out the flag. Rather than reverse the hash algorithm, we simulated it, giving it a known password, and checking the result against known algorithms. Unsurprisingly, it was off-the-shelf SHA256.

With this understanding in place, we went looking for a place to exploit. The only place our input is handled is in the function we named `parse_and_maybe_set_flag_printer()`. It does a bizarre dance summarized below:
  1. `alloca()` space for the two numbers, `memcpy()` them over and `strtol()` them.
  2. `alloca()` space for the password, but do nothing with it yet.
  3. `alloca()` space for the username, `memcpy()` it over, and search the list for a match.
  4. If it finds a match, `memcpy()` the password over, hash it and compare.

The code checks whether the numbers we submit are negative, but it doesn't check for int overflows. Which don't match, but gave us the right idea. By claiming the password is unsually long, we can cause the stack to grow until it overlays the heap. With a carefully chosen value, the value we submit as the 'username' will be written to an arbitrary place on the heap.

Using this, we choose a new password, hash it, and overwrite the backdoor accounts password hash with our hash. Then we log in. Flag.

### Bluetooth Device Manager
[Detailed Notes](bluetooth_device_manager/notes.md)

In this challenge, we get to interact with a simple interface that allows us to configure and modify a list of "connected" devices. This challenge took me much longer than it should have, because I didn't pay attention to exact function of the `brcc` and `brcs` opcodes. There's an off-by-one error in the function we named `broken_read_str_until_13b()`. Just from initial analysis we knew that it didn't always null-terminate, but thought that was it.

Also, we read the victory string: "such heap, much pr0!", and guessed that it might be an attack on `malloc()` or `free()`. I'd recently done a challenge where a broken `malloc()` implementation was the target, so I ended up fully reversing both those functions, to no avail. That was dumb. In the context of this challenge, I should have just compared them to the known-good versions in other levels. It's not like Riscure would have deliberately left such a vulnerability in all levels.

Once we identified the correct vulnerability (the off-by-one error), we realized what that meant. The ability to overflow heap strings means the ability to modify the malloc entries between the heap strings. Details are in the linked notes file, but the summary is:
  1. Create heap strings A, B, C, D
  2. Delete B
  3. Overflow A to modify the size of B in the freelist, so that it overlaps with C
  4. Create a padding entry in the formerly-B-freespace to use up some
  5. Create a payload entry that overlaps the part of C. that contains the struct
  6. Write to the element created in 5 to alter where the struct points
  7. Write to C to write where the struct points.

All that done, we just need to tick the relevant boxes. Write 0xBAADF00D to the relevant address, and overwrite a return address with the victory function.

### Climate Controller Catastrophe
[Detailed Notes](climate_controller_catastrophe/notes.md)

At 750 points, we expected this one to be rough, and we were not disappointed. We start the challenge out with one **major** hint. The organizers provided us with a .hex file that will wipe the contents of the EEPROM. Immediately this suggests to us that we can brick the challenge by writing bad values to the EEPROM, which turned out to be true. Going with this, we need to understand how we can write to the EEPROM, and how the board will react to the contents of it.

First things first, we need to interact with the board. The serial line just prints out some initialization messages then goes silent. No amount of prodding there produces a result. Breaking out a logic analyzer, and probing all the A# and D# channels, we saw traffic on D7, D9, D10, D11, and D13. Checking out the [board schematic](TODO XXX /riscurino.png), we found that most of those lines are inputs to the CAN controllers. We spent a little while fuzzing the CAN interface, but got nothing. So instead, we read the SPI traffic on board init. From that we learned that it was masking all traffic except from a couple SIDs like 0x665, and was running at 100 kHz. Cool, we have interaction.

At this point we spent about a week reverse engineering the .hex file. Here's a list of the things we learned:
  * It accepts CAN traffic from 0x776 as well as 0x665
  * The flag printing function isn't called from anywhere, we're going to need to gain control of $pc.
  * Before we invoke that function, we need to set global variable `must_be_1337_10210A` to 0x1337, or else the flag will be masked.
  * There's a global we called `eeprom_write_lock_1020f0` that controls write access to the EEPROM. We need to satisfy a "Diffie-Hellman" challenge to get it.
  * They did DH wrong, the equation is `C = R^E (mod M)`, solve for 'E', but they ask us to solve for 'R'. To solve that all we need to do is factor the modulus, and use a well-known algorithm.
  * The "certificate" we can upload to EEPROM needs to satisfy a very particular format or else it will be wiped and replaced by the default.
  * We need to mark the EEPROM cert as "uninitialized" so that it gets parsed on startup.
  * The function `cert_check_valid_6297()` is called with a length 0x100 buffer, but internally it uses three length 100 buffers. The opens up an overflow of the third.

With the overflow point established, we need to build a ROP chain that will set `must_be_1337_10210A`, and invoke `print_flag_or_die_4E8F()`. The easiest target I saw was to return to the tail of an ISR, which is going to populate almost all of the registers. Once we had that, and a function like `sub_34e2()` that invokes `memmove()` near its return to get our write-what-where, it was all over.

Result: a board that prints the flag to serial on boot, every boot.

Funny story: The INT0_ ISR that we used for our first ROP gadget sets `r1` along with so many other variables, and I stuck `0x31` there as a placeholder... code starts to act _real strange_ when you change the value of zero...

## CAN Bus

## Side Channel Analysis

## Fault Injection

## :Shruggie:


