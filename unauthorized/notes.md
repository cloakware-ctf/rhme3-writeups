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

I got an updated *full compromise* idb from jonathan and used bindiff to import some function names.

I poked aruond the write eeprom functions and noticed that detect fault injection is writing a flag to address 0 of the eeprom.

I found also that what was marked as eeprom_mapen is actually implementing a read of eeprom address

I annotated all the callsites of the write and read of eeprom with the addresses to/from and the values when known. Eeprom is being used to preserve RNG test parameters and also to preserve FI tests.

The code that is testing someting and then optionally calling what I'm pretty sure is a flag printer, `ROM:068A test_something_and_set_flag_printer` is referring to malloc'd buffers of 100 34 byte structures; the last of which points to a 9byte buffer that gets the contents 'backdoor' as setup by `ROM:05DD setup_100_34b_structs_and_one_backdoor`

The function that reads in characters up to an expected terminator takes a maximum size; it won't let you overflow the buffer that is passed to it.

When we supply input, it wants the line to be of the form `[name_length]:[password_length]:[name][password]`. We can't supply more than 200 bytes to `read_str_until`; but we can set the size of both name and password buffers when parsed... maybe?

## Subi Subci

Not really sure about this AVR construct; there is a mix of places in the code where carry is handled in subtraction of immeadiates from 16bit vairables stored in pairs of registers. Sometimes with a `subci -1` like below; sometimes not. I'm guess that the net effect is as I marked up in the comments but I can't convince myself that it is

```
movw    r22, YL
subi    r22, -0x1F
sbci    r23, -1         ; buffer = Y+0x1f
```

