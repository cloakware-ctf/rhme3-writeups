# AVR ICSP with Atmel ICE

Atmel ICE AVR Port (corrected/reversed numbering)

10 | TCK  | GND   | 9
8  | TDO  | VTG   | 7
6  | TMD  | nSRST | 5
4  | NC   | nTRST | 3
2  | TDI  | GND   | 1

Atmel ICE SAM Port (corrected/reversed numbering)

10 | VTG  | TMS   | 9
8  | GND  | TCK   | 7
6  | GND  | TDO   | 5
4  | NC   | TDI   | 3
2  | GND  | nRST  | 1

## Standard ICSP Pinout

ICSP

1 | MISO   | VCC  | 2
3 | SCK    | MOSI | 4
5 | nRESET | GND  | 6

### Mapping to ICSP

7  VTG   -> VCC
2  TDI   -> MOSI
1  GND   -> GND
5  nSRST -> nRESET
10 TCK   -> SCK
8  TDO   -> MISO

## MatrixStorm AVR Stick JTAG+PDI

42 |     |          | 36
54 |     |          | 37
55 |     |          | 38
43 |     |          | 39
12 | TCK |          | 40
13 | TDO |          | 41

11 | TDI | PDI_Data | 56
10 | TMS | PDI_CLK  | 57
 9 |     |          | 58
 8 |     |          | 59
 7 |     |          | VCC
 6 |     |          | GND

## AVR Port to PDI Mapping

1 GND   -> GND
5 nSRST -> PDI_CLK
7 VTG   -> VCC
8 TDO   -> PDI_DATA
