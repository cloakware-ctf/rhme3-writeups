Notes for RHME3 key fob challenge

## Links

* http://www.ce.ewi.tudelft.nl/fileadmin/ce/files/colloquium/1209_Amitabh_Das.pdf

* http://ieeexplore.ieee.org/document/6733305/

* http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.367.7107&rep=rep1&type=pdf

* http://btw.tttc-events.org/material/EBTW06//EBTW06%20Presentations/EBTW06-4-2-Novak.pdf

* http://trudevice.com/Workshop/program/22%20A.%20Biasizzo%20-2-%20TRUDEVICE_2013.pdf

* https://pdfs.semanticscholar.org/189e/cdfe1d187a6e623ad4dd1c3ec4576e55628e.pdf

* https://file.scirp.org/pdf/JSEA_2016033117200055.pdf



## Notes

scan chain could refer to JTAG (IEEE 1149.1) or IEEE 1500 (for SoCs) or even  IEEE P1687 IJTAG

There are UNLOCK instructions for JTAG; finding the actual IR code isn't simple. But the IRCODE space is small; so brute-forcing the unused IRCODE space is possible -- since we know we have a challenge-response; we should look for something coming back at us with 'random looking' challenges

...

After much probing with JTAGulator it became clear that this was not a JTAG scan chain. There was a pattern on TDO after a long clk pulse train that mimic'd the signals on what was then TMS; so quite likely TMS was some kind of MOSI line that was getting clocked 'around' the scan chain

Headed over to MPSSE programming;

-----------------------------------------
| Description | C232HM Cable Color Code |
-----------------------------------------
| CS          | Brown                   |
| MISO        | Green                   |
| GND         | Black                   |
| MOSI        | Yellow                  |
| CLK         | Orange                  |
| Vcc         | Red                     |
-----------------------------------------

...

I coded up a script to pulse the LATCH based on the way that TDI+TMS are toggled wrt TCK in JTAG BYPASS scans. B/c I remember seeing the self-destruct message when running the BYPASS scan with the TDI/TMS swapped. `test_low_pulse.py` -- results in the self-destruct message but only a chain of ff's getting shifted-out

Actually it seems more like I trigger the self-destruct on the second-time.

## More Notes

We found out there was a bug and a patched firmware. Some notes from above were lost in careless rsync'ing by me --but it doesn't matter now since there was a bug!

Starting over: is this a JTAG scan chain? If so, then the rate-limiting patch on the JTAGulator FW should detect it

### JTAGulating

* I patched the jtagulator firmware to drive no fast than 1.8KHz

* I connected A[5:2] in parallel to the JTAGulator CH[0:3] and Logic Analyzer[1:4] 

* let er rip

--> Sadly, same result. This is not a sacn-chain that understands IR codes -- or at least does not understand the BYPASS ircode. The logic capture taken during the BYPASS scan shows a signal on TDO that mirrors the TMS line; so it has the same behavior as before. Best bet is to poke it with slow-SPI as before.

### Slow Poking

