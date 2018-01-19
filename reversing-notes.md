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
