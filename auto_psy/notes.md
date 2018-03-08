
## Auto-Psy

## Candump
Note: serial is empty. No traffic.

When split, I only see traffic on can0.
Split Traffic:
(3925.369) can0 7E5#0209000000000000
(3925.874) can0 7E5#02090A0000000000
(3927.388) can0 7E5#0201000000000000
(3927.893) can0 7E5#02010D0000000000
(3928.903) can0 7DF#0201000000000000
(3929.407) can0 7DF#0201200000000000
(3929.912) can0 7DF#0201400000000000
(3930.417) can0 7DF#0201420000000000

That's basically it.

When linked, I see the following:
	* order not preserved
	* unique messages only

can0: (4190.195) 7E5#02:09000000000000
can1: (4190.208) 7ED#06:49004040000000

can0: (4185.653) 7E5#02:090A0000000000
can1: (4185.666) 7ED#1016:490A50777254
can1: (4185.670) 7ED#21:7261696E5F4374
can1: (4185.675) 7ED#22:726C0000000000
can1: (4185.680) 7ED#23:00000000000000

can0: (4186.662) 7E5#02:01000000000000
can1: (4186.675) 7ED#06:41000008000300

can0: (4187.167) 7E5#02:010D0000000000
can1: (4187.180) 7ED#03:410D8D00000000


can0: (4193.729) 7DF#02:01000000000000
can1: (4193.742) 7ED#06:41000008000300

can0: (4193.729) 7DF#02:01200000000000
can1: (4193.742) 7ED#06:41200000000100

can0: (4194.234) 7DF#02:01400000000000
can1: (4194.247) 7ED#06:41404000001000

can0: (4194.234) 7DF#02:01420000000000
can1: (4194.247) 7ED#04:41422ee0000000

## Ben's Take
	0. understand UDS
	1. set up a security session
	2. memory read

PS: scapy does UDS, I'm seeing fragments of a ISO-TP

## UDS research
BLG-Notes.pptx, page 63-6

Format:
	byte length, bytes data
	or
	byte 10 = multi-frame
	byte length, bytes data
	byte 2x = fragment, bytes data
	
Examples:
	7e0#01:28 -> service $28 - communications control
	7e0#02:2701 - get seed for Security Access (possibly 2702?)
	-> 7e8#04: 67 01 YYYY - the seed?
	7e0#04:27 02XXXX - send secret code
	-> 7e8:02 6702 - correct
	-> 7e8:03 7f27 - wrong
	- possibly it tracks number of attempts and you'd need to reset if exceeded

What we have might be a custom variant

