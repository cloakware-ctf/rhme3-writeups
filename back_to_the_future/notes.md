
## Challenge
Our intelligence suggests that the DeLorean we previously recovered is capable of time travel.
According to the documents in our possession the time travel functionality is activated as soon as a specific ECU within the vehicle maintains a velocity of exactly 88 miles per hour for at least a few seconds. We rely on your CAN bus expertise to trick the time-travel ECU into thinking it is travelling at the right speed; again, the vehicle dashboard we restored should be of use.

Best of luck.

The Dashboard app is available here.

Challenge developed by Argus Cyber Security.

## Basics:
```sh
sudo ip link set can0 type can bitrate 49500 listen-only off
sudo ip link set can0 up
candump -cae can0,0:0,#FFFFFFFF
```

Pinning the speedometer
```sh
while true; do cansend can0 023#00580d0520 ; done
```

## What's wrong:
```
(1520451177.520598) can0 202#004C004A52
(1520451177.562015) can0 023#0020080C10
(1520451177.566454) can0 19A#7110
(1520451177.644743) can0 023#0020080C10
(1520451177.649195) can0 19A#7110
(1520451177.673535) can0 10C#004A0130004C004B
(1520451177.678214) can0 1BF#000C000E000C
(1520451177.682538) can0 012#061E
(1520451177.745651) can0 023#0020080210
(1520451177.750104) can0 19A#7110
(1520451177.846613) can0 023#002007F810
(1520451177.851048) can0 19A#7110
(1520451177.875363) can0 10C#004A0137004B004A
(1520451177.880085) can0 1BF#000C000E000C
(1520451177.884448) can0 012#061E
(1520451177.962667) can0 023#002107EE10
(1520451177.967131) can0 19A#7110
(1520451177.990922) can0 202#004C004A52
(1520451178.050484) can0 023#002107E410
(1520451178.054947) can0 19A#7110
(1520451178.079237) can0 10C#004A0137004A004A
(1520451178.083970) can0 1BF#000C000E000C
(1520451178.088312) can0 012#061E
(1520451178.185709) can0 023#002107DA10
(1520451178.190177) can0 19A#7110
(1520451178.250343) can0 023#002207D010
(1520451178.254788) can0 19A#7110
(1520451178.279106) can0 10C#004A0137004A004B
(1520451178.283809) can0 1BF#000C000E000C
(1520451178.288124) can0 012#061E
(1520451178.385576) can0 023#002207D010
(1520451178.390042) can0 19A#7110
(1520451178.487527) can0 023#002207D010
(1520451178.491964) can0 19A#7110
(1520451178.516274) can0 10C#004B0137004A004C
(1520451178.520970) can0 1BF#000C000E000C
(1520451178.525302) can0 012#061E
(1520451178.530890) can0 202#004C004B52
(1520451178.572308) can0 023#002107D010
(1520451178.576752) can0 19A#7110
(1520451178.655029) can0 023#002107C610
(1520451178.659493) can0 19A#7110
(1520451178.683808) can0 10C#004B0137004B004B
(1520451178.688517) can0 1BF#000C000E000C
(1520451178.692828) can0 012#061E
(1520451178.772140) can0 023#002107BC10
(1520451178.776562) can0 19A#7110
(1520451178.892229) can0 023#002107BC10
(1520451178.896694) can0 19A#7110
(1520451178.920969) can0 10C#004B0137004B004B
(1520451178.925720) can0 1BF#000C000E000C
(1520451178.930030) can0 012#061E
(1520451178.971964) can0 023#002207BC10
(1520451178.976417) can0 19A#7110
(1520451179.000151) can0 202#004B004B52
(1520451179.059726) can0 023#002207C610
(1520451179.064226) can0 19A#7110
(1520451179.088537) can0 10C#004B0137004B004C
(1520451179.093252) can0 1BF#000C000E000C
(1520451179.097543) can0 012#061E
(1520451179.158648) can0 023#002207C610
(1520451179.163117) can0 19A#7110
(1520451179.259569) can0 023#002307C610
(1520451179.264038) can0 19A#7110
(1520451179.288407) can0 10C#004B0137004C004C
(1520451179.293067) can0 1BF#000C000E000C
(1520451179.297406) can0 012#061E
(1520451179.375620) can0 023#002307C610
(1520451179.380115) can0 19A#7110
(1520451179.461406) can0 023#002307C610
(1520451179.465904) can0 19A#7110
(1520451179.490245) can0 10C#004B011F004C004B
(1520451179.494930) can0 1BF#000C000E000C
(1520451179.499245) can0 012#061E
(1520451179.504802) can0 202#004B004B52
```

```
TEMP_Value = 75
MAF_Value = 288
Text_Value = 0
MPH_Value = 34
RPM_Value = 2030
BATT_Value = 12
Text_Value = 0
TEMP_Value = 75
MAF_Value = 288
BATT_Value = 12
Text_Value = 1
MPH_Value = 33
RPM_Value = 2060
Text_Value = 0
MPH_Value = 33
RPM_Value = 2060
TEMP_Value = 74
MAF_Value = 288
Text_Value = 1
BATT_Value = 12
MPH_Value = 33
RPM_Value = 2060
Text_Value = 0
MPH_Value = 33
RPM_Value = 2060
TEMP_Value = 74
MAF_Value = 288
Text_Value = 0
BATT_Value = 12
AAC_Value = 77
TEMP_Value = 74
Text_Value = 1
MPH_Value = 33
RPM_Value = 2050
TEMP_Value = 74
MAF_Value = 288
Text_Value = 1
BATT_Value = 12
MPH_Value = 32
RPM_Value = 2050
Text_Value = 0
TEMP_Value = 74
MAF_Value = 295
MPH_Value = 32
RPM_Value = 2050
BATT_Value = 12
Text_Value = 0
MPH_Value = 32
RPM_Value = 2050
Text_Value = 0
TEMP_Value = 74
MAF_Value = 295
MPH_Value = 32
RPM_Value = 2050
BATT_Value = 12
Text_Value = 0
AAC_Value = 76
TEMP_Value = 74
Text_Value = 0
MPH_Value = 33
RPM_Value = 2040
TEMP_Value = 74
MAF_Value = 295
```

## Understanding the CAN messages
Two new CAN messages.

### can0  023   [5]  00 20 08 02 10            '. ...'
	0020: MPH
	0802: RPM
	  10: unknown, sometimes 20

### can0  19A   [2]  71 10                     'q.'
	71: unknown
	10: unknown, matches preceeding 023[2]
	when 023 unknown is 20, this ends with 20 too

------------------------------------------------------------------------

### can0  10C   [8]  00 4A 01 20 00 4A 00 4A   '.J. .J.J'
	004a: TEMP
	0120: MAF
	004a: unknown, is active
	004a: unknown, is active

### can0  1BF   [6]  00 0C 00 0E 00 0C         '......'
	000c: BATT
	000e: unknown
	000c: unknown

### can0  012   [2]  06 21                     '.!'
	0621: unknown, 1569 decimal
	also seen 1600:1609, 060a:0628
	seems to stop at 1600

------------------------------------------------------------------------

### can0  202   [5]  00 4C 00 4A 52            '.L.JR'
	004c: AAC
	004a: TEMP (redundant)
	52: unknown, is active

------------------------------------------------------------------------

## Getting rid of the engine light
If I send 19A# messages every 10ms I don't see the light.
If I send 023# messages every 10ms I can pin the speedometer
	* need to go faster if I'm sending more messages

## Plan
	checkout python: USB-scapy
	creating usb sessions, challenge response, memory read
	load up Auto-psy, see if we can make it work

## Splitting It Up
Ben cut the link between CAN1 and CAN2, now I can check them each out separately.

### Case 0: dumping CAN 2, CAN 1 isolated.
candump: nil
dashboard: all zeros
serial: 9 messages, all zero bodies, they stop coming

Sending: no response to any message.

### Case 1: dumping CAN 1, CAN 2 isolated.
candump: 023, 19a, 202
dashboard: all zeros
serial: 9 messages, all zero bodies, they stop coming
Note: didn't see any 10c/1bf/012 sequence.

Sending: it receives 10c, updates TEMP, eventually MAF, eventually BATT
	~10 seconds between msg and dashboard update of TEMP
	another 10 seconds for MAF, another 10 seconds for BATT
	further waiting produced nothing

### Case 2: connecting both
This is a double-CAN setup. Using two USB<->CAN adapters.

Adapter pinout: white:L, red:H, green:ground

candump0: 10c, 1bf, 012
candump1: 023, 19a, 202
dashboard: all zeros

Doesn't need to receive anything to keep happily sending.

Sending: has effects similar to to sending to the linked CAN.

Solved!
	- We knew that spamming 19A would suppress the engine light
	- So every time we see any message on CAN, we send one. 
	- Also, alter every message 023 to be speed 88 miles per hour
	- Also, cut traces so that contradicting messages don't get through.

