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