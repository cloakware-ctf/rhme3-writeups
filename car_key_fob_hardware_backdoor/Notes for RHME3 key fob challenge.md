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
