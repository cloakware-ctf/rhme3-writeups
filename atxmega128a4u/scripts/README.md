Use these scripts to work around problems with the avr processor module in IDA (6.95 or 7.0)

| | |
|---------|--------------------------------------------|
| `avr_data_vector_names.py` | rename some registers to identify them as the data vector halves (XL, XH, YL, YH, ZL, ZH) -- works only on binary images, not on elfs |
| `fix_IDA_xmega128a4u.py` | 'delete' the mapped area registers, the XMEGA doesn't have this but IDA assumes it does -- works only on binary images, not on elfs |
| `avr_loader_loop_copy.py` | define functions to emulate the loader loops to get the data segment in the idb populated and the bss segment zeroed -- works only on binary images, not on elfs |
| `avr_dumb_seq_load_xrefs.py` | treat all pairs of loads of immeadiates into sequential registers as data references, improves manual analysis because IDA doesn't make complex offsets on register loads || `avr2idacfg.py` | convert ATFD (basically XML) processor definitions from Atmel into IDA Pro in an `avr.cfg` |

Here is an example session creating `ransom.idb`;

0. install the python deps: sark and idascript
0. copy the `ATXMega128A4u.cfg` in `../resources/` to `~/idapro/cfg/avr.cfg`
1. start by opening the `.hex` file with AVR processor and auto-analysis disabled.
2. select the ATXMega128A4u processor
3. put this into the python console

```
Python>runscript('.../rhme3/atxmega128a4u/scripts/avr_data_vector_names.py')
Python>runscript('.../rhme3/atxmega128a4u/scripts/fix_IDA_xmega128a4u.py')
Python>runscript('.../rhme3/atxmega128a4u/scripts/avr_loader_loop_copy.py')
Python>avr_loader_emu(0x2324, 0x2000, 0x2174)
Python>avr_bss_emu(0x2174,0x223D)
```

4. run auto-analysis (i.e. go click the circle-cross button)
5. put this into the python console

```
Python>runscript('.../rhme3/atxmega128a4u/scripts/avr_dumb_seq_load_xrefs.py')
Python>runscript('.../rhme3/atxmega128a4u/scripts/avr_codatafy.py')
Python>dref_all_fixer()
```

