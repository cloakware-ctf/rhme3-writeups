> inverted block frequency is inconsistent
appears by default

> IO pulse inverted line is not connected correctly
appears by default

> unexpected blockfrequency indicate
appears randomly

What happens when we just connect A0 to D[0..13] ?

| connection | different message |
|------------|-------------------|
| A0 -> D2 | +"audio active line signal does not conform to the expected model" |
| A0 -> D3 |  |
| A0 -> D4 | +"audio active line signal does not conform to the expected model" |
| A0 -> D5 |  |
| A0 -> D6 | +"IO prepare line is not corrected correctly" |
| A0 -> D9 | +"IO pulse AND IO pulse inverted lines are not connected correctly" |
| A0 -> D10 | +"IO bridge line is not connected correctly" |
| A0 -> D11 | +"IO bridge line is not connected correctly" |
| A0 -> D12 |  |
| A0 -> D13 |  |

So:

| pin | function-name sink |
|-----|---------------|
| D2 | audio active line |
| D3 | |
| D4 | audio active line |
| D5 | |
| D6 | IO prepare line |
| D9 | IO pulse line |
| D10 | IO bridge line |
| D11 | IO bridge line |
| D12 | |
| D13 | |

I've got a gut feel that A5 is the 'IO pulse inverted' and A3 is 'IO pulse'.

What happens when we connect A5 to the D[0..13] ?

| connection | different message |
|------------|-------------------|
| A5 -> D2 |  |
| A5 -> D3 |  |
| A5 -> D4 | -"IO pulse inverted line is not connected correctly" |
| A5 -> D5 | -"IO pulse inverted line is not connected correctly" |
| A5 -> D6 | +"IO Prepare line is not connected correctly" |
| A5 -> D9 | +"IO pulse AND IO pulse inverted lines are not connected correctly" |
| A5 -> D10 | +"IO bridge line is not connected correctly" |
| A5 -> D11 | +"IO bridge line is not connected correctly" |
| A5 -> D12 | +"IO bridge line is not connected correctly" |
| A5 -> D13 |  |

So:

| pin | function-name sink|
|-----|---------------|
| D2 | audio active line |
| D3 | |
| D4 | audio active line / IO pulse inverted line |
| D5 | IO pulse inverted line|
| D6 | IO prepare line |
| D9 | IO pulse line |
| D10 | IO bridge line |
| D11 | IO bridge line |
| D12 | |
| D13 | |

My guess:

| pin | function-name source|
|-----|---------------|
| A0  |  |
| A1 | audio active line |
| A2 | block frequency indicate? |
| A3 | IO pulse line |
| A4 | |
| A5 | IO pulse inverted line |

Try:

| Connections | Change in messages |
|-------------|--------------------|
| A1 -> D2 , A3 -> D9 , A5 -> D5 | -"IO pulse inverted line is not connected correctly" (i.e. only complains about unexpected block frequency indicate) |
| '', A3 -> D10 | '' |
| '', A3 -> D11 | '' |
| '', A3 -> D12 | '' |
| '', A3 -> D13 | '' |
| '', A3 -> D3 | -"unexpected blockfrequency indicate" +"audio active line signal does not conform to the expected model" (i.e. only complains about the audio active line ). I once heard +"block frequency does not match inverse"|
| '', A3 -> D4 | +"audio active line signal does not conform to the expected model" |
| aborted | --- |

My guess:

| pin | function-name sink (+ for confirmed)|
|-----|---------------|
| D2 |  |
| D3 | block frequency indicate line (+)|
| D4 | audio active line |
| D5 | IO pulse inverted line (+)|
| D6 | IO prepare line |
| D9 | IO pulse line (+) |
| D10 | IO bridge line |
| D11 | IO bridge line |
| D12 | |
| D13 | |

| pin | function-name source  (+ for confirmed) |
|-----|---------------|
| A0  |  |
| A1 | audio active line |
| A2 | block frequency indicate (+) |
| A3 | IO pulse line (+) |
| A4 | |
| A5 | IO pulse inverted line (+) |

Try:

| Connections | Change in messages |
|-------------|--------------------|
| A1 -> D4 , A2 -> D3, A3 -> D9 , A5 -> D5 | only "IO bridge line is not connected correctly" |
| aborted | --- |

My guess:

| pin | function-name sink (+ for confirmed)|
|-----|---------------|
| D2 |  |
| D3 | block frequency indicate line (+)|
| D4 | audio active line (+) |
| D5 | IO pulse inverted line (+)|
| D6 | IO prepare line |
| D9 | IO pulse line (+) |
| D10 | IO bridge line |
| D11 | IO bridge line |
| D12 | |
| D13 | |

| pin | function-name source  (+ for confirmed) |
|-----|---------------|
| A0  | IO prepare |
| A1 | audio active line (+) |
| A2 | block frequency indicate (+) |
| A3 | IO pulse line (+) |
| A4 | IO bridge |
| A5 | IO pulse inverted line (+) |

Try:

| Connections | Change in messages |
|-------------|--------------------|
| A0 -> D6, A1 -> D4 , A2 -> D3, A3 -> D9 , A5 -> D5 | only "IO bridge line is not connected correctly" |
| A0 -> D6, A1 -> D4 , A2 -> D3, A4 -> D10, A3 -> D9 , A5 -> D5 | +"block frequency does not match inverse" +"io prepare line is not connected correctly" |
| A0 -> D6, A1 -> D4 , A2 -> D3, A4 -> D11, A3 -> D9 , A5 -> D5 | +"block frequency does not match inverse" +"io prepare line is not connected correctly" + "io bridge line is not connected correctly |
| aborted | --- |

My guess:

| pin | function-name sink (+ for confirmed)|
|-----|---------------|
| D2 | IO prepare line |
| D3 | block frequency indicate line (+)|
| D4 | audio active line (+) |
| D5 | IO pulse inverted line (+)|
| D6 |  |
| D9 | IO pulse line (+) |
| D10 | IO bridge line (+) |
| D11 | |
| D12 | |
| D13 | |

| pin | function-name source  (+ for confirmed) |
|-----|---------------|
| A0  | IO prepare |
| A1 | audio active line (+) |
| A2 | block frequency indicate (+) |
| A3 | IO pulse line (+) |
| A4 | IO bridge |
| A5 | IO pulse inverted line (+) |

Try:

| Connections | Change in messages |
|-------------|--------------------|
| A0 -> D2, A1 -> D4 , A2 -> D3, A3 -> D9 , A4 -> D10, A5 -> D5 | +"inverted block frequency is inconsistent" |
| A4 -> D2, A1 -> D4 , A2 -> D3, A3 -> D9 , A0 -> D10, A5 -> D5 | +"inverted block frequency is inconsistent" + "IO bridge line is not connected correctly" |

My guess:

| pin     | pin | function-name sink (+ for confirmed)| note      |
|---------|-----|-------------------------------------|-----------|
| A0      | D2  | IO prepare line (/ orinverted clock?)   | could be A0,A2,A4 |
| A2      | D3  | block frequency indicate line (+)   | could be A0,A2,A4 |
| A1 (+)  | D4  | audio active line (+)               | not A4, A2, or A0|
| A5 (+)  | D5  | IO pulse inverted line (+)          | not A3    |
|         | D6  |                                     |           |
| A3 (+)  | D9  | IO pulse line (+)                   | not A5    |
| A4 (+)  | D10 | IO bridge line (+)                  | not A0 / not stable with A2|
|         | D11 |                                     |           |
|         | D12 |                                     |           |
|         | D13 |                                     |           |

can't find a combination to stop "inverted block frequency is inconsistent" and/or "block frequency does not match inverse"

disconnecting D2 -> "clock frequency does not match inverse"
conecting D2+A0 -> "inverted clock frequency is inconsistent"

---

The next night:

There are many pins which I think I have *fixed*. IO Prepare is weird; seems to cause both errors about IO prepare and also errors about clock frequency (not block frequency). The clock frequency indicate line obviously wants something with a regular frequency' the only two lines that have a regular frequency are A4 which is confirmed as "IO Bridge" and A1 which is confirmed as audio active. So let's try routing those signals to both the line where we've confirmed them and also to D2 and D3.

NB: "block frequency does not match inverse" only occurs when "inverted clock frequency is inconsistent" does not. This suggests that the system is checking for a consistent inverted clock and *then* checking for matching the inverse.


Try:

as above, and A0 -> D2 + A0 -> D3 => "inverted clock frequency is inconsistent"
as above, and A4 -> D2 + A4 -> D3 => "inverted clock frequency is inconsistent"
as above, and A0 -> D2 + A4 -> D3 => "inverted clock frequency is inconsistent"
as above, and A4 -> D2 + A0 -> D3 => "inverted clock frequency is inconsistent"

with nothing connected to D2; we get "unexpected clock frequency indicate"

with all other pins grounded: we get "unexpected clock frequency indicate"

NB: just after audio, the behaviour of the pins change; most go away; A0 switches to a clock and A2 switches to a pulse train (but regular enough to also be a clock)

as above, and A2 -> D2 + GND -> D3 => "inverted clock frequency is inconsistent"
as above, and GND -> D2 + A2 -> D3 => "inverted clock frequency is inconsistent"

It really seems like the three errors about clock frequency occur at at random

as above, and OC -> D2 + OC -> D3 => "inverted clock frequency is inconsistent"
as above, and A3 -> D2 + OC -> D3 => "inverted clock frequency is inconsistent"
as above, and OC -> D2 + A3 -> D3 => "block frequency does not match inverse"
as above, and A5 -> D2 + A3 -> D3 => "block frequency does not match inverse"

A5 is the IO pulse inverted line (kinda like the inverse of D2), so that's weird

removed grounds of other pins, unchanged

scanned A5 across the remaining pins:
with A5 -> D6 (OC -> D2 etc. as above): "IO prepare line is not connected correctly"
with A5 -> D12 (OC -> D2 etc. as above): "IO prepare line is not connected correctly"
with A5 -> D13 (OC -> D2 etc. as above): "IO prepare line is not connected correctly"

| pin     | pin | function-name sink (+ for confirmed)| note      |
|---------|-----|-------------------------------------|-----------|
| ??      | D2  | clock?                              | could be A0,A2,A4 not A5 |
| A3?     | D3  | inverted clock?                     | could be A0,A2,A4 |
| A1 (+)  | D4  | audio active line (+)               | not A4, A2, or A0|
| A5 (+)  | D5  | IO pulse inverted line (+)          | not A3    |
| OC      | D6  | IO Prepare Line (+)                 | wants to be OC? |
| A3 (+)  | D9  | IO pulse line (+)                   | not A5    |
| A4 (+)  | D10 | IO bridge line (+)                  | not A0 / not stable with A2|
|         | D11 |                                     |           |
| OC      | D12 | IO Prepare Line (+)                 | wants to be OC? |
| OC      | D13 | IO Prepare Line (+)                 | wants to be OC? |

So I made an inverter from an XOR gate I had no yet soldered into a boldport club papillon project. This created ~A3

as above, and ~A3 -> D2 + A3 -> D3 => "clock frequency does not match inverse"
as above, and ~A3 -> D11 + A3 -> D3 => "clock frequency does not match inverse"
as above, and ~A3 -> D12 + A3 -> D3 => "clock frequency does not match inverse"
as above, and ~A3 -> D13 + A3 -> D3 => "clock frequency does not match inverse"

I was trying other signals to create inverted pairs; trying to do it with A5 resulted in persistent "IO Prepare line is connected incorrectly" and then after power cycle the board would boot. Luckily it could still be flashed.

trying different combinations; only A2 -> D3 or A3 -> D3 (along with the other connections) wil stop the "unexpected clock frequency indicate" and "inverted clock frequency is inconsistent", yielding "clock frequency does not match inverse"

I tried the same as ~A3 above with ~A2 -- same results: all "clock frequency does not match inverse"

I verified that the inverter I rigged up is in fact functioning as expected (again)

I tried the same as ~A3 above with ~A1 -- same results

I resorted to just poking pins with the oscilloscope. Not sure if it is due to the connection of the other pins so far or not; but the SCA and SCL pins (named for I2C) had inverted-matching pulsed-clocked signals on them. this was not there in phonic1

but connecting those to D2 or D3 does nothing anyways -- then I poked with the scope again and those signals were gone.

I recconected A1 / ~A1 to D2 / D3. The signals came back. SCL responds to D3 and SDA responds to D2. They actually mirror the D pins. They aren't iverting. Also the response time of the SCL/SDA pins to the D pins is almost immeadiate with no jitter. It doesn't look digitally handled at all.

---

The next next night:

I'm trying to scan VCC across all the input pins this time. To confirm pin names and also I might discover something. I don't treat SCL or SDA as input b/c I observed outputs on them mirroring the D2 D3 pins last time around. But let's try out other inputs on the board break-out: Vin and RX.

Here's all the messages; listed in the order they are emitted

* [@1a] "unexpected clock frequency detected"
* [@1b] "inverted clock frequency is inconsistent"

* [@3a] "Audio active line does not conform to the expected model"

* [@2a] "IO prepare line is not connected correctly"
* [@2b] "IO Pulse inverted line is not connected correctly"
* [@2c] "IO Bridge line is not connected correctly"
* [@2d] "IO Pulse AND IO Pulse inverted line is not connected correctly"

* [@1c] "clock frequency does not match inverse"

| connection | messages  (~ - sometimes) | Any names correlated |
|------------|---------------------------|----------------------|
| VCC -> D13 | [@1a] [@2b] | IO Pulse Inverted |
| GND -> D13 | | |
| VCC -> D12 | [@1a] [@2c] [@2d] | IO Bridge, IO Pulse, IO Pulse Inverted |
| GND -> D12 | | |
| VCC -> D11 | [@1a] ~[@1b] [@2c] [@2d] | IO Bridge, IO Pulse, IO Pulse Inverted |
| GND -> D11 | | |
| VCC -> D10 | [@1a] ~[@1b] [@2c] [@2d] | IO Bridge, IO Pulse, IO Pulse Inverted |
| GND -> D10 | | |
| VCC -> D9  | [@1a] ~[@1b] [@2c] [@2d] | IO Bridge, IO Pulse, IO Pulse Inverted |
| GND -> D9  | | |
| VCC -> D6  | [@1a] [@2a] | IO Prepare |
| GND -> D6  | [@1a] [@2a] [@2b] | Audio active, IO Pulse inverted |
| VCC -> D5  | [@1a] [@2a] | IO Prepare |
| GND -> D5  | ~[@1a] [@3a] [@2b] | Audio active, IO Pulse inverted |
| VCC -> D4  | [@1b] [@2a] | IO Prepare, Inverted Clock |
| GND -> D4  | [@3a] [@2b] | Audio active, IO Pulse inverted |
| VCC -> D3  | [@1a] ~[@1b] [@2a] | IO Prepare |
| GND -> D3  | [@1c] [@3a] [@2b] | Audio activ, IO Pusle inverted |
| VCC -> D2  | [@1a] ~[@1b] ~[@2b] | |
| GND -> D2  | [@1a] ~[@1b] [@2b] [@3a] | Audio active, IO Pulse inverted |
| VCC -> RX  | [@1a] ~[@1b] ~[@2b] | |
| GND -> RX  | [@1a] ~[@1b] [@2b] [@3a] | Audio active, IO Pulse inverted |
| VCC -> Vin | [@1a] [@2b] | IO Pulse Inverted |
| GND -> Vin | [@1a] [@2b] | IO Pulse Inverted |

Pretty bananas actually -- no real correlation. But I do have a better list of the messages. And Jonathan corrected my hearing on some words, so altogether better.

Let's try to get the clock errors sorted out and *then* the other lines.

| D2  | D3  | D4 | D5 | D6 | D9 | D10 | D11 | D12 | D13 | RX  | Vin | connection    | input name     | [@1a] | [@1b] | [@3a] | [@2a] | [@2b] | [@2c] | [@2d] | [@2e] | [@1c] | Notes |
|-----|-----|----|----|----|----|-----|-----|-----|-----|-----|-----|---------------|----------------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-|
|     |     |    |    |    |    |     |     |     |     |     |     | none          |                |  X    |       | X     |       | X     |       |       |       |       | |
|     | A3  |    |    |    |    |     |     |     |     |     |     |   A3 -> D3    | inv clock?     |       |       | X     |       | X     |       |       |       | ~     | |
|     | ''  | A1 |    |    |    |     |     |     |     |     |     | + A1 -> D4    | audio active   |       |       |       |       | X     |       |       |       |       | |
|     | ''  | '' | A5 |    |    |     |     |     |     |     |     | + A5 -> D5    | io pulse inv   |       |       |       |       |       | X     |       |       | ~     | |
|     | ''  | '' | '' |    |    | A4  |     |     |     |     |     | + A4 -> D10   | io bridge      |       |       |       |       |       |       |       |       | X     | |
| A2  | ''  | '' | '' |    |    | ''  |     |     |     |     |     | + A2 -> D2    | clock?         |       | X     |       |       |       |       |       |       |       | |
| A3  | A2  | '' | '' |    |    | ''  |     |     |     |     |     | +- A2 <-> A3  | clock & inv?   |       | X     |       |       |       |       |       |       |       | |
|     | A2  | '' | '' |    |    | ''  |     |     |     |     |     | +- A2 -> D3   | clock & inv?   |       |       |       |       |       |       |       |       | X     | |
|     | A1  | '' | '' |    |    | ''  |     |     |     |     |     | +- A1 -> D3   | inv clock ?    | X     | ~     |       |       |       |       |       |       |       | |
|     | A4  | '' | '' |    |    | ''  |     |     |     |     |     | +- A4 -> D3   | inv clock ?    | X     |       |       |       |       |       |       |       |       | |
|     | A5  | '' | '' |    |    | ''  |     |     |     |     |     | +- A5 -> D3   | inv clock ?    | X     |       |       |       |       |       |       |       |       | |
|     | A3  | '' | '' |    |    | ''  |     |     |     |     |     | +- A3 -> D3   | inv clock ?    |       |       |       |       |       |       |       |       | X     | |
| A5  | ''  | '' | '' |    |    | ''  |     |     |     |     |     | +  A5 -> D2   | clock ?        |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     |     |     | A5  |     | +- A5 -> RX   | serial rx      |       |       |       | ~     |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     |     |     |     | A5  | +- A5 -> Vin  | Vin            |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     |     | A5  |     |     | +- A5 -> D13  | ?              |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     | A5  |     |     |     | +- A5 -> D12  | ?              |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  | A5  |     |     |     |     | +- A5 -> D11  | ?              |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    | A5 | ''  |     |     |     |     |     | +- A5 -> D9   | IO Pulse       |       |       |       |       |       |       |       | X     |       | |
|     | ''  | '' | '' | A5 |    | ''  |     |     |     |     |     | +- A5 -> D6   | IO prepare     |       |       |       | X     |       |       |       |       |       | |
| ~A1 | ''  | '' | '' |    |    | ''  |     |     |     |     |     | +- ~A1 -> D2  | clock?         | X     |       |       |       |       |       |       |       |       | |
| ~A3 | ''  | '' | '' |    |    | ''  |     |     |     |     |     | +- ~A3 -> D2  | clock?         |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     |     |     | ~A3 |     | +- ~A3 -> RX  | serial rx      |       |       |       | ~     |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     |     |     |     | ~A3 | +- ~A3 -> Vin | Vin            |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     |     | ~A3 |     |     | +- ~A3 -> D13 | ?              |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     | ~A3 |     |     |     | +- ~A3 -> D12 | ?              |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  | ~A3 |     |     |     |     | +- ~A3 -> D11 | ?              |       |       |       |       |       |       |       |       | X     | |
|     | ~A4 | '' | '' |    |    | ''  |     |     |     |     |     | +- ~A4 -> D13 | inv clock      | X     |       |       |       |       |       |       |       |       | |
|     |  A2 | '' | '' |    |    | ''  |     |     |     |     |     | +- A2 ->  D13 | inv clock      |       |       |       |       |       |       |       |       | X     | |
|     |     |    |    |    |    |     |     |     |     |     |     | none          |                |  X    |       | X     |       | X     |       |       |       |       | |
|     | A2  |    |    |    |    |     |     |     |     |     |     |   A2 -> D3    | inv clock?     |       |       | X     |       | X     |       |       |       | X     | |
|     | ''  | A1 |    |    |    |     |     |     |     |     |     | + A1 -> D4    | audio active   |       |       |       |       | X     |       |       |       | ~     | |
|     | ''  | '' | A5 |    |    |     |     |     |     |     |     | + A5 -> D5    | io pulse inv   |       |       |       |       |       | X     |       |       | ~     | |
|     | ''  | '' | '' |    |    | A4  |     |     |     |     |     | + A4 -> D10   | io bridge      |       |       |       |       |       |       |       |       | X     | |
| ~A2 | ''  | '' | '' |    |    | ''  |     |     |     |     |     | +- ~A2 -> D2  | clock?         |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     |     | ~A2 |     |     | +- ~A2 -> D13 | ?              |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  |     | ~A2 |     |     |     | +- ~A2 -> D12 | ?              |       |       |       |       |       |       |       |       | X     | |
|     | ''  | '' | '' |    |    | ''  | ~A2 |     |     |     |     | +- ~A2 -> D11 | ?              |       |       |       |       |       |       |       |       | X     | |
|     |     |    |    |    |    |     |     |     |     |     |     | none          |                |  X    |       | X     |       | X     |       |       |       |       | |
|     | 7Khz|    |    |    |    |     |     |     |     |     |     | 7K 50% -> D3  | inv clock?     |       | ~     |       |       | X     |       |       |       | ~     | I setup a 7KHz 50% duty cycle 3.3v clock from a bus pirate |
|     | ''  | A1 | A5 |    |    | A4  |     |     |     |     |     | + usual       |                |  ~    | ~     |       |       |       |       |       |       | X     | |
|~7Khz| ''  | '' | '' |    |    | ''  |     |     |     |     |     | +- ~7K -> D2  | clock?         |       |       |       |       |       |       |       |       | X     | |

I also did logic captures at the same time and confirmed that the signals coming out of the A[0..5] aren't changing from what was captured before

Here's all the messages; listed in the order they are emitted

* [@1a] "unexpected clock frequency detected"
* [@1b] "inverted clock frequency is inconsistent"

* [@3a] "Audio active line does not conform to the expected model"

* [@2a] "IO prepare line is not connected correctly"
* [@2b] "IO Pulse inverted line is not connected correctly"
* [@2c] "IO Bridge line is not connected correctly"
* [@2d] "IO Pulse AND IO Pulse inverted line is not connected correctly"
* [@2e] "IO Pulse line is not connected correctly"

* [@1c] "clock frequency does not match inverse"

## Another night

This time we wired it up so that every D[2..15] has a pull-up.

| D2  | D3  | D4 | D5 | D6 | D9 | D10 | D11 | D12 | D13 | RX  | Vin |                                | [@1a] | [@1b] | [@3a] | [@2a] | [@2b] | [@2c] | [@2d] | [@2e] | [@1c] | Notes |
|-----|-----|----|----|----|----|-----|-----|-----|-----|-----|-----|--------------------------------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-|
|     |     |    |    |    |    |     |     |     |     |     |     |                                |       | X     |       | X     |       | X     |       | X     |       | |
| A3  | A5  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       |       | X     | |
| A2  | A5  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | X     | D2 maybe pulse line |
| A0  | A5  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | X     | |
|-----|-----|----|----|----|----|-----|-----|-----|-----|-----|-----|--------------------------------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-|
|     |     |    |    |    |    |     |     |     |     |     |     |                                |       | X     |       | X     |       | X     |       | X     |       | |
|     |     |    | A5 |    | A3 |     |     |     |     |     |     |                                |       | X     |       | X     |       | X     |       |       |       | |
|     |     |    | '' |    | '' | A4  |     |     |     |     |     |                                | X     | ~     |       | X     |       |       |       |       |       | |
|     |     |    | '' | A0 | '' | ''  |     |     |     |     |     |                                | X     | ~     |       | ~     |       |       |       |       |       | |
|     |     |    | '' | A1 | '' | ''  |     |     |     |     |     |                                | X     |       |       | X     |       |       |       |       |       | |
|     |     |    | '' | A2 | '' | ''  |     |     |     |     |     |                                | X     | ~     |       |       |       |       |       |       |       | |
|     |     |    | '' |    | '' | A0  |     |     |     |     |     |                                | X     | ~     |       | X     |       | ~     |       |       |       | |
|     |     |    | '' |    | '' | A2  |     |     |     |     |     |                                | X     | ~     |       | X     |       |       |       |       |       | so either A2 or A4 are OK on D10 |
|     | A0  |    | '' |    | '' | ''  |     |     |     |     |     |                                |       | X     |       | X     |       |       |       |       |       | |
|     | ''  |    | '' | A2 | '' | ''  |     |     |     |     |     |                                |       | ~     |       | X     |       |       |       |       |       | D6 might be a clock line |
|-----|-----|----|----|----|----|-----|-----|-----|-----|-----|-----|--------------------------------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-|
|     |     |    |    |    |    |     |     |     |     |     |     |                                | X     | ~     |       | X     |       | X     |       | X     |       | |
| A4  |     |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | X     | |
| ''  | A4  |    |    |    |    |     |     |     |     |     |     |                                | ~     | X     |       | X     |       | X     |       | X     |       | inverted clock line is D3? |
|     | ''  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | X     | |
| A3  | A3  |    |    |    |    |     |     |     |     |     |     |                                | ~     | X     |       | X     |       | X     |       | X     |       | |
| A3  | A5  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | X     | |
| A5  | A3  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | X     | |
|-----|-----|----|----|----|----|-----|-----|-----|-----|-----|-----|--------------------------------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-|
| A3  |~A3  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | X     | |
|~A3  | A3  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | ~     | no @1c on first boot |
|~A2  | A2  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | ~     | no @1c on first boot |
|~A1  | A1  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | X     | |
| A1  |~A1  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | ~     | no @1c on first boot |
| A1  |~A1  |    |    | A0 | A3 | A4  |     |     |     |     |     |                                |       |       |       |       |       |       |X      |       |       | no @1c in later cycles |
| A1  |~A1  |    | A5 | A0 | A3 | A4  |     |     |     |     |     |                                |       |       | X     |       |       |       |       |       | X     | |
| A1  |~A1  | A1 | A5 | A0 | A3 | A4  |     |     |     |     |     |                                |       |       |       |       |       |       |       |       | X     | |
|~A2  | A2  | A1 | A5 | A0 | A3 | A4  |     |     |     |     |     |                                |       |       |       | X     |       |       |       |       | X     | |
|~A3  | A3  | A1 | A5 | A0 | A3 | A4  |     |     |     |     |     |                                |       |       |       | X     |       |       |       |       | X     | |
|-----|-----|----|----|----|----|-----|-----|-----|-----|-----|-----|--------------------------------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-|

* we noticed that the errors switch from @1a -> @1b and null -> @2c on the third cycle after hard reset -- when things are connected wrong (we think)
	* because of this we adopted the procedure of hard-reboot first time
* this time around the @1c error can appear even when the @2X errors are present
	* this lets us focus on getting the clock right first -- b/c the signals may in fact be re-sync'd by the clock lines

## YA NIGHT

Again, with pullups. Last time around we managed to stop the @1c errors in some cases; this is promising in light of the fact that the @1c errors seemed terminal a week ago.

* [@1a] "unexpected clock frequency detected"
* [@1b] "inverted clock frequency is inconsistent"

* [@3a] "Audio active line does not conform to the expected model"

* [@2a] "IO prepare line is not connected correctly"
* [@2b] "IO Pulse inverted line is not connected correctly"
* [@2c] "IO Bridge line is not connected correctly"
* [@2d] "IO Pulse AND IO Pulse inverted line is not connected correctly"
* [@2e] "IO Pulse line is not connected correctly"

* [@1c] "clock frequency does not match inverse"

| D2  | D3  | D4 | D5 | D6 | D9 | D10 | D11 | D12 | D13 | RX  | Vin |                                | [@1a] | [@1b] | [@3a] | [@2a] | [@2b] | [@2c] | [@2d] | [@2e] | [@1c] | Notes |
|-----|-----|----|----|----|----|-----|-----|-----|-----|-----|-----|--------------------------------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-|
|     |     |    |    |    |    |     |     |     |     |     |     |                                |       | X     |       | X     |       | X     |       | X     |       | |
|~A4  | A4  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | X     | |
| ''  | ''  |    |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | ~     | no @1c on first boot |
| ''  | ''  | A1 |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | ~     | '' |
| ''  | ''  | A0 |    |    |    |     |     |     |     |     |     |                                |       |       | X     | X     |       | X     |       | X     | ~     | '', A0 is not Audio Active Signal |
| ''  | ''  | A2 |    |    |    |     |     |     |     |     |     |                                |       |       | X     | X     |       | X     |       | X     | ~     | '', A2 '' |
| ''  | ''  | A3 |    |    |    |     |     |     |     |     |     |                                |       |       | X     | X     |       | X     |       | X     | ~     | '', A3 '' |
| ''  | ''  | A4 |    |    |    |     |     |     |     |     |     |                                |       |       | X     | X     |       | X     |       | X     | ~     | '', A4 '' |
| ''  | ''  | A5 |    |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | ~     | '' |
| ''  | ''  | A1 | A5 |    |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | ~     | '' |
| ''  | ''  | '' |    | A5 |    |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | ~     | '' |
| ''  | ''  | '' |    |    | A5 |     |     |     |     |     |     |                                |       |       |       | X     |       | X     |       | X     | ~     | '' |
| ''  | ''  | '' | A5 | A0 | A3 | A4  |     |     |     |     |     |                                |       |       |       |       |       |       |       |       | X     |    |
| ''  | ''  | '' | A5 | A0 | A3 |     |     |     |     |     |     |                                |       |       |       |       |       | X     |       |       |       |    |
| ''  | ''  | '' | A5 | A0 |    | A4  |     |     |     |     |     |                                |       |       |       | ~     |       |       |       | X     | ~     | there's some kind of relationship btw IO Prepare and clock   |
| ''  | ''  | '' | A5 |    | A3 | A4  |     |     |     |     |     |                                |       |       |       | X     |       |       |       |       | ~     |  |
| ''  | ''  | '' |    | A0 | A3 | A4  |     |     |     |     |     |                                |       |       |       |       | X     |       |       |       | X     |  |
|-----|-----|----|----|----|----|-----|-----|-----|-----|-----|-----|--------------------------------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-|
| ''  | ''  | '' | A5 | A0 | A3 |~A4  |     |     |     |     |     |                                |       |       |       | ~     |       | X     |       |       | ~     | @2a and @1c occur together after four cycles |
| A4  |~A4  | '' | '' | '' | '' |~A4  |     |     |     |     |     |                                |       |       |       |       |       | X     |       |       | X     |  |
| A4  |~A4  | '' | '' | '' | '' | A4  |     |     |     |     |     |                                |       |       |       | X     |       |       |       |       | ~     |  |
|~A1  | A1  | '' | '' | '' | '' | ''  |     |     |     |     |     |                                |       |       |       | ~     |       |       |       |       | X     |  |

