* These scripts showed me how to handle the .atdf files in python
  * some python that is a good start at parsing the Atmel xml files: `https://github.com/abcminiuser/gdp/blob/c15f7f7bc545c321bd9956f0701e628b170e047f/devices/device_atmelstudio.py`
  * a stand-alone script that could be useful: `https://github.com/wrightflyer/test/blob/fd17c7e0810f2fede0fd658406144d578b531b58/avrread.py`

* IDA uses `.cfg` files to handle variants of the AVR processors. The default installed `avr.cfg` has alot of options but does not have the ATxmega128a4u which we are using in rhme3

* Downloading the 'packs' (`.atdf`) files for both our ATxmega128a4u and some of the chip variants in the default `avr.cfg` showed that the ATxmega128a4u is different in at least one way that is very important to IDA pro:
  * whereas the other ATMegas in the default `avr.cfg` all expose their register file as the first thing in data-address space ('RAM' segment to IDA) -- the ATxmega128a4u starts with GPIO0 control registers and starts filling-in with the other ioports after that

* This seems benign but will cause us big problems in a little bit

* I wrote a python script to parse the xml `atdf` files and create a customized `.cfg` from all the data. When running it on our `ATxmega128a4u.atdf` the result is, naturally, a cfg which does not map the register file first in the data space, it starts with `GPIO0`

* IDA Pro's avr cpu module `procs/avr.imc` always puts the regist file at the start of RAM and then fills-in the ioports defined in `avr.cfg` after that.
  * when it uses the custom config for the ATxmega128a4u it still assumes the register file is first and then starts with the GPIO0 ioport at `+0x20` afterwards
  * IDA also aparently uses the names of the addresses from RAM:0x0 to RAM:0x20 as the register names

* I spent some time reversing the `avr.imc` module to see if there is any syntax in the `cfg` file ot handle this situation and found none

* I wrote a script to 'fix' the ioports in RAM, by moving them back by 0x20. This resulted in the registered being renamed; e.g.

```
ROM:0160 sub_160:                                ; CODE XREF: sub_313+10p
ROM:0160                 push    r28
ROM:0161                 push    r29
ROM:0162                 in      r28, CPU_SPL    ; Stack Pointer Low
ROM:0163                 in      r29, CPU_SPH    ; Stack Pointer High
ROM:0164                 ldi     r24, 0x50 ; 'P'
ROM:0165                 ldi     r25, 0
ROM:0166                 ldi     r18, 0x50 ; 'P'
ROM:0167                 ldi     r19, 0
ROM:0168                 movw    r30, r18
ROM:0169                 ld      r18, Z
ROM:016A                 ori     r18, 2
ROM:016B                 movw    r30, r24
ROM:016C                 st      Z, r18
ROM:016D                 nop
ROM:016E
ROM:016E loc_16E:                                ; CODE XREF: sub_160+17j
ROM:016E                 ldi     r24, 0x51 ; 'Q'
ROM:016F                 ldi     r25, 0
ROM:0170                 movw    r30, r24
ROM:0171                 ld      r24, Z
ROM:0172                 mov     r24, r24
ROM:0173                 ldi     r25, 0
ROM:0174                 andi    r24, 2
ROM:0175                 clr     r25
ROM:0176                 or      r24, r25
ROM:0177                 breq    loc_16E
ROM:0178                 ldi     r24, 0xD8 ; '�'
ROM:0179                 out     CPU_CCP, r24    ; Configuration Change Protection
ROM:017A                 ldi     r24, 1
ROM:017B                 sts     unk_100040, r24
ROM:017D                 ldi     r24, 0x50 ; 'P'
ROM:017E                 ldi     r25, 0
ROM:017F                 ldi     r18, 0x50 ; 'P'
ROM:0180                 ldi     r19, 0
ROM:0181                 movw    r30, r18
ROM:0182                 ld      r18, Z
ROM:0183                 andi    r18, 0xFE
ROM:0184                 movw    r30, r24
ROM:0185                 st      Z, r18
ROM:0186                 pop     r29
ROM:0187                 pop     r28
ROM:0188                 ret
ROM:0188 ; End of function sub_160
```

changed into:

```
ROM:0160 sub_160:                                ; CODE XREF: sub_313+10p
ROM:0160                 push    VPORT3_DIR      ; Push Register on Stack
ROM:0161                 push    VPORT3_OUT      ; Push Register on Stack
ROM:0162                 in      VPORT3_DIR, CPU_SPL ; In Port
ROM:0163                 in      VPORT3_OUT, CPU_SPH ; In Port
ROM:0164                 ldi     VPORT2_DIR, 0x50 ; 'P' ; Load Immediate
ROM:0165                 ldi     VPORT2_OUT, 0   ; Load Immediate
ROM:0166                 ldi     VPORT0_IN, 0x50 ; 'P' ; Load Immediate
ROM:0167                 ldi     VPORT0_INTFLAGS, 0 ; Load Immediate
ROM:0168                 movw    VPORT3_IN, VPORT0_IN ; Copy Register Word
ROM:0169                 ld      VPORT0_IN, Z    ; Load Indirect
ROM:016A                 ori     VPORT0_IN, 2    ; Logical OR with Immediate
ROM:016B                 movw    VPORT3_IN, VPORT2_DIR ; Copy Register Word
ROM:016C                 st      Z, VPORT0_IN    ; Store Indirect
ROM:016D                 nop                     ; No Operation
ROM:016E
ROM:016E loc_16E:                                ; CODE XREF: sub_160+17j
ROM:016E                 ldi     VPORT2_DIR, 0x51 ; 'Q' ; Load Immediate
ROM:016F                 ldi     VPORT2_OUT, 0   ; Load Immediate
ROM:0170                 movw    VPORT3_IN, VPORT2_DIR ; Copy Register Word
ROM:0171                 ld      VPORT2_DIR, Z   ; Load Indirect
ROM:0172                 mov     VPORT2_DIR, VPORT2_DIR ; Copy Register
ROM:0173                 ldi     VPORT2_OUT, 0   ; Load Immediate
ROM:0174                 andi    VPORT2_DIR, 2   ; Logical AND with Immediate
ROM:0175                 clr     VPORT2_OUT      ; Clear Register
ROM:0176                 or      VPORT2_DIR, VPORT2_OUT ; Logical OR
ROM:0177                 breq    loc_16E         ; Branch if Equal
ROM:0178                 ldi     VPORT2_DIR, 0xD8 ; '�' ; Load Immediate
ROM:0179                 out     CPU_CCP, VPORT2_DIR ; Out Port
ROM:017A                 ldi     VPORT2_DIR, 1   ; Load Immediate
ROM:017B                 sts     CLK_CTRL, VPORT2_DIR ; Control Register
ROM:017D                 ldi     VPORT2_DIR, 0x50 ; 'P' ; Load Immediate
ROM:017E                 ldi     VPORT2_OUT, 0   ; Load Immediate
ROM:017F                 ldi     VPORT0_IN, 0x50 ; 'P' ; Load Immediate
ROM:0180                 ldi     VPORT0_INTFLAGS, 0 ; Load Immediate
ROM:0181                 movw    VPORT3_IN, VPORT0_IN ; Copy Register Word
ROM:0182                 ld      VPORT0_IN, Z    ; Load Indirect
ROM:0183                 andi    VPORT0_IN, 0xFE ; Logical AND with Immediate
ROM:0184                 movw    VPORT3_IN, VPORT2_DIR ; Copy Register Word
ROM:0185                 st      Z, VPORT0_IN    ; Store Indirect
ROM:0186                 pop     VPORT3_OUT      ; Pop Register from Stack
ROM:0187                 pop     VPORT3_DIR      ; Pop Register from Stack
ROM:0188                 ret                     ; Subroutine Return
ROM:0188 ; End of function sub_160
```

* so any ioport in the first 0x20 bytes can't be renamed or else the disassembly gets bonkers

* we can use this to our advantage though too: I can rename the X- Y- and Z- data vector parts XL,XH,YL,YH,ZL,ZH. I wrote a script to do this.

* I *did not* fix the memory mapped ioports; left them alone, but did rename the data vector parts
  * the `out` and `in` instructions reference the correct ATxmega128a4u ioports; anything else will not
  * the data vector part registers are renamed

* at this point the `RESET_` function had a clear loader loop;

```
ROM:0138 RESET_:                                 ; CODE XREF: TRNCOMPL__0j
ROM:0138
ROM:0138 ; FUNCTION CHUNK AT ROM:1190 SIZE 00000002 BYTES
ROM:0138
ROM:0138                 clr     r1              ; Clear Register
ROM:0139                 out     CPU_SREG, r1    ; Status Register
ROM:013A                 ser     YL              ; Set Register
ROM:013B                 out     CPU_SPL, YL     ; Stack Pointer Low
ROM:013C                 ldi     YH, 0x3F ; '?'  ; Load Immediate
ROM:013D                 out     CPU_SPH, YH     ; Stack Pointer High
ROM:013E                 ldi     r16, 0          ; Load Immediate
ROM:013F                 out     CPU_EIND, r16   ; Extended Indirect Jump
ROM:0140                 out     CPU_RAMPD, r1   ; Ramp D
ROM:0141                 out     CPU_RAMPX, r1   ; Ramp X
ROM:0142                 out     CPU_RAMPY, r1   ; Ramp Y
ROM:0143                 out     CPU_RAMPZ, r1   ; Ramp Z
ROM:0144                 ldi     r17, 0x21 ; '!' ; Load Immediate
ROM:0145                 ldi     XL, 0           ; Load Immediate
ROM:0146                 ldi     XH, 0x20 ; ' '  ; Load Immediate
ROM:0147                 ldi     ZL, 0x24 ; '$'  ; Load Immediate
ROM:0148                 ldi     ZH, 0x23 ; '#'  ; Load Immediate
ROM:0149                 ldi     r16, 0          ; Load Immediate
ROM:014A                 out     CPU_RAMPZ, r16  ; Ramp Z
ROM:014B                 rjmp    loc_14E         ; Relative Jump
ROM:014C ; ---------------------------------------------------------------------------
ROM:014C
ROM:014C loc_14C:                                ; CODE XREF: RESET_+18j
ROM:014C                 elpm    r0, Z+          ; Extended Load Program Memory
ROM:014D                 st      X+, r0          ; Store Indirect
ROM:014E
ROM:014E loc_14E:                                ; CODE XREF: RESET_+13j
ROM:014E                 cpi     XL, 0x74 ; 't'  ; Compare with Immediate
ROM:014F                 cpc     XH, r17         ; Compare with Carry
ROM:0150                 brne    loc_14C         ; copy from PROG:0x2324 to DATA:0x2000-0x2174
ROM:0151                 out     CPU_RAMPZ, r1   ; Ramp Z
ROM:0152                 ldi     r18, 0x22 ; '"' ; Load Immediate
ROM:0153                 ldi     XL, 0x74 ; 't'  ; Load Immediate
ROM:0154                 ldi     XH, 0x21 ; '!'  ; Load Immediate
ROM:0155                 rjmp    loc_157         ; Relative Jump
ROM:0156 ; ---------------------------------------------------------------------------
ROM:0156
ROM:0156 loc_156:                                ; CODE XREF: RESET_+21j
ROM:0156                 st      X+, r1          ; Store Indirect
ROM:0157
ROM:0157 loc_157:                                ; CODE XREF: RESET_+1Dj
ROM:0157                 cpi     XL, 0x3D ; '='  ; Compare with Immediate
ROM:0158                 cpc     XH, r18         ; Compare with Carry
ROM:0159                 brne    loc_156         ; fill 0x2174-0x223D with 0x0
ROM:015A                 call    sub_313         ; Call Subroutine
ROM:015C                 jmp     loc_1190        ; Jump
ROM:015C ; End of function RESET_
```

* The BSS location is obviously 0x2174-0x223D. The RW/initialized variables segment appears to be 0x2000-0x2174; however, the source address 0x2324 is wayyyy past the only strings in the ROM; so this loader loop won't help us find any xrefs to the strings.

* I then fixed all the ioport locations except for the ones that were in the first 0x20; what I found was the `out` and `in` instructions were only working with CPU_ block ioports, nothing possibley related to uart or aes. By scrolling though the data area looking at xrefs, I could see the only program xrefs to the memory mapped locations were into now-unknown addresses (other than `CLK_CTRL`)

```
RAM:0053                 .byte 1
RAM:0054 unk_100054:     .byte 1                 ; DATA XREF: sub_160+19r
RAM:0055                 .byte 1
RAM:0056                 .byte 1
RAM:0057                 .byte 1
RAM:0058 unk_100058:     .byte 1                 ; DATA XREF: RESET_+8r
RAM:0059 unk_100059:     .byte 1                 ; DATA XREF: RESET_+9r
RAM:005A unk_10005A:     .byte 1                 ; DATA XREF: RESET_+Ar
RAM:005B unk_10005B:     .byte 1                 ; DATA XREF: RESET_+Br
RAM:005B                                         ; RESET_+12r ...
RAM:005C unk_10005C:     .byte 1                 ; DATA XREF: RESET_+7r
RAM:005D unk_10005D:     .byte 1                 ; DATA XREF: RESET_+3r
RAM:005D                                         ; sub_160+2r ...
RAM:005E unk_10005E:     .byte 1                 ; DATA XREF: RESET_+5r
RAM:005E                                         ; sub_160+3r ...
RAM:005F unk_10005F:     .byte 1                 ; DATA XREF: RESET_+1r
RAM:0060 DFLLRC32M_CTRL: .byte 1                 ; Control Register
```

* with these two facts it would seem that the layout of this image is still incorrect (somehow) in IDA Pro.

* comparing the contents of ROM as viewed by radare2, it would seem that the 0x2324 address is correct and contains the strings of interest no less

```
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF  comment
0x00002324  feca a008 4006 0408 0220 b009 6006 4080  ....@.... ..`.@.
0x00002334  0a20 2530 3258 000a 0a59 6f75 7220 6361  . %02X...Your ca
0x00002344  7220 6973 2074 616b 656e 2068 6f73 7461  r is taken hosta
0x00002354  6765 2062 7920 5245 5645 4e41 4e54 544f  ge by REVENANTTO
0x00002364  4144 2072 616e 736f 6d77 6172 6520 7665  AD ransomware ve
0x00002374  7273 696f 6e20 4445 4255 475f 6134 6661  rsion DEBUG_a4fa
0x00002384  6538 3663 2e0a 0054 6f20 6765 7420 796f  e86c...To get yo
0x00002394  7572 2063 6172 2062 6163 6b2c 2073 656e  ur car back, sen
0x000023a4  6420 796f 7572 2075 7365 7220 4944 3a0a  d your user ID:.
0x000023b4  2573 0a00 0a61 6e64 2024 3133 3337 2074  %s...and $1337 t
0x000023c4  6f20 7468 6520 666f 6c6c 6f77 696e 6720  o the following
0x000023d4  7268 6d65 3363 6f69 6e20 6164 6472 6573  rhme3coin addres
0x000023e4  733a 200a 5b43 454e 534f 5245 445d 2e0a  s: .[CENSORED]..
0x000023f4  0a41 6c72 6561 6479 2070 6169 643f 2054  .Already paid? T
0x00002404  6865 6e20 656e 7465 7220 7468 6520 7265  hen enter the re
0x00002414  6365 6976 6564 2075 6e6c 6f63 6b20 636f  ceived unlock co
0x00002424  6465 2068 6572 653a 0a00 4974 2077 6173  de here:..It was
0x00002434  2061 2070 6c65 6173 7572 6520 646f 696e   a pleasure doin
0x00002444  6720 6275 7369 6e65 7373 2077 6974 6820  g business with
0x00002454  796f 752e 0a59 6f75 7220 6361 7220 6973  you..Your car is
0x00002464  206e 6f77 2075 6e6c 6f63 6b65 642e 0a48   now unlocked..H
0x00002474  6572 6520 6973 2061 2062 6f6e 7573 3a0a  ere is a bonus:.
0x00002484  000a 4861 7665 2061 206e 6963 6520 6461  ..Have a nice da
0x00002494  7921 0a00 ffff ffff ffff ffff ffff ffff  y!..............
```

* So IDA is screwing up the PROG and DATA address spaces for this AVR.

* indeed: IDA thinks the RESET_ handler is at 0x138; the jmp instruction in the vector points to 0x270 though; and this is what radare2 reports as well

```
ROM:0138 RESET_:                                 ; CODE XREF: TRNCOMPL__0j
ROM:0138
ROM:0138 ; FUNCTION CHUNK AT ROM:1190 SIZE 00000002 BYTES
ROM:0138
ROM:0138                 clr     r1              ; Clear Register
```

```
            ;-- entry0:
            ;-- pcl:
            0x00000270      1124           clr r1
            0x00000272      1fbe           out 0x3f, r1                ; '?' ; IO SREG: flags
```

* similarly, the string of interest is supposedly at 0x119E in IDA pro, but is exactly where we think it should be in r2

```
ROM:119E aYourCarIsTaken:.db 0xA,"Your car is taken hostage by REVENANTTOAD ransomware version DE
```

```
[0x0000233d]> px
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0000233d  596f 7572 2063 6172 2069 7320 7461 6b65  Your car is take
0x0000234d  6e20 686f 7374 6167 6520 6279 2052 4556  n hostage by REV
0x0000235d  454e 414e 5454 4f41 4420 7261 6e73 6f6d  ENANTTOAD ransom
0x0000236d  7761 7265 2076 6572 7369 6f6e 2044 4542  ware version DEB
0x0000237d  5547 5f61 3466 6165 3836 632e 0a00 546f  UG_a4fae86c...To
0x0000238d  2067 6574 2079 6f75 7220 6361 7220 6261   get your car ba
0x0000239d  636b 2c20 7365 6e64 2079 6f75 7220 7573  ck, send your us
0x000023ad  6572 2049 443a 0a25 730a 000a 616e 6420  er ID:.%s...and
0x000023bd  2431 3333 3720 746f 2074 6865 2066 6f6c  $1337 to the fol
0x000023cd  6c6f 7769 6e67 2072 686d 6533 636f 696e  lowing rhme3coin
0x000023dd  2061 6464 7265 7373 3a20 0a5b 4345 4e53   address: .[CENS
0x000023ed  4f52 4544 5d2e 0a0a 416c 7265 6164 7920  ORED]...Already
0x000023fd  7061 6964 3f20 5468 656e 2065 6e74 6572  paid? Then enter
0x0000240d  2074 6865 2072 6563 6569 7665 6420 756e   the received un
0x0000241d  6c6f 636b 2063 6f64 6520 6865 7265 3a0a  lock code here:.
0x0000242d  0049 7420 7761 7320 6120 706c 6561 7375  .It was a pleasu
```

* r2 treats as bytewise. I'm pretty sure that this is false since calls are encoded with word-wise addresses.

* I wrote a script to emulate the avr loader and bss loops

```
Python>runscript('/Users/ben.gardiner/Documents/rhme3/atxmega128a4u/scripts/avr_loader_loop_copy.py')
Python>avr_loader_emu(0x2324, 0x2000, 0x2174)
Python>avr_bss_emu(0x2174,0x223D)
```

* The result was some xrefs into the data segment, but we were missing references to the aparent start of the strings

* I noticed that the only xrefs present were from instructions which had the coplete address encoded as an immediate. It appears that there are no coplex offsets built by AVR analysis
  * we needed a a plugin/script/other to scan and build xrefs based on loads into multiple registers. I suspected the data vectors. The question was how to decide how far backwards to search for the value of the register -- the typical problem with building complex offsets in static analysis I'm sure

* My teammate noticed that the address to the first insteresting string 0x2017 was being loaded into a pair of sequential registers, and twice in fact. Like is looked like the compiler was dumbly using the pair of registers to set the full value and then ignoring that it had half the value in a register already
  * I had read in the Cisco writeup for RHME(1) that they wrote a script to build data xrefs from loads into pairs of sequential registers.
  * These two pieces of info were reason enough to create only this dumb form of building xrefs.

* I wrote a script to do this in ~1hr and we started having more visibility into the firmware. e.g. the 0x1337 address/constant? was observed. This was a good sign.

* I tried to build signatures for the libc's I could find but found that flair does not support processor type '83' !

* Not through the woods yet, though, there were still no xrefs to any USART registers; how is it doing UART communications?

* Time passes; the leaves change color etc.

* It seems pretty clear that the registers are regularly being used in pairs; same with stack locations.

* Stack frame is almost always setup in Y

* We learn of the `*w` family of instructions which work with pairs of registers at the same time; now alot more assembly makes sense

* We try using FLAIR; contact hexrays. FLAIR will never work on anything that addresses in 16bit 'bytes'

* Bindiff works OK. Need to redploy the bindiff.jar file since that isn't installed in the right location. Need to remember that it does not 'see' immeadiates.

* We build a sample project for the atxmega128a4u; open it in IDA. Use bindiff to bring the symbols over to the IDB we're analyzing. We use the `--whole-archive` flag to get all the object files in there for more 'symbolicating'.

* except, bindiff only works in IDA 6.95 and only IDA 7.0 seems to know how to load all the symbols from a AVR studio ELF file.

* I write more baloney idapython scripts to export all the functions from an IDB and import them back. Do the former in IDA 7.0 on the sample project and the latter in 6.95 on the sample project. Then we have something to bindiff against.

* We find that there are no serial routines used; but a few low-level functions are recognized.

* We find and rebuild the RHME2 source code; the serial routines (after tweaking flags) are easy to spot visually. But for some reason bindiff refuses to match them.

* We identify the serial read and write functions.

* We get Atmel Studio simulator runnign the .hex files by first converting them to an object file. Then we can actually debug them. Helps alot.

* We identify which serial port ioports are in use. We identify the buffer address used. IDA has a type 'offset in current segment' that is useful when trying to find xrefs in DATA segment. The serial port ioports are there in memory, for USARTC. There isn't a clear reference to the buffer address.

* ...

* By combining data printed by the challenge binary with simulation of the RE binary (via memory edits in the simulator) , Jonathan was able to predict the key for the crackme.

## Links for later

* https://www.radare.org/get/avrworkshops2016.pdf

* https://vimeo.com/211371081 and http://radare.org/get/r2snow.pdf

* http://thanat0s.trollprod.org/2014/01/loader-un-binaire-arduino-dans-ida/
