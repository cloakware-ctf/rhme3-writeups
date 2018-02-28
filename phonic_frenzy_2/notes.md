
## Logic Analyzer
AREF is all over the place.
Other D lines all passive, except RX/TX, and D7/D8

A5 is wrapping A3
A4 is wrapping A2, but there is a clear A2<->A0 relationship
	- A0 flips or flops right before A2 pulses
	- A4 is wrapping A2 and A1

Full sequence
	A4 high: A5 wraps some A3 pulses
	A4 low: A0, A1, A2 do their thing
		- A0 toggles 2-3 times
		- after each A0 toggle, A2 pulses high for 10us
			- or stays low, in which case next A0 pulse is ~3us away
		- in after an A2 pulse, A1 drops low once
		- that low drop //may// contain a A2 pulse
		-

## Timing Analysis
Serial
	0. RESET
	5. Welcome to the Infotainment Center.
	15. This unit has been disabled for security reasons.
	20. The wiring harness appears to be missing or connected incorrectly. Please check the connections and try again.
	38. The system will reboot now.

Therefore: record on `This unit has been disabled...`
Stop on `The system will reboot now.`

Audio
	0. RESET
	5. Welcome to the Infotainment Center.
	9. Verifying that the secure hardware interface is connected correctly.
	15. This unit has been disabled for security reasons.
	19. The wiring harness appears to be connected incorrectly.
	25. inverted clock frequency is inconsistent
	30. audio packet line signal does not conform to the expect model
	37. I/O pulse inverted line is not connected correctly.
	42. Please check the wiring.
	45. The system will reboot now.

## Ben's Text Shorthands
* [@1a] "unexpected clock frequency detected"
* [@1b] "inverted clock frequency is inconsistent"

* [@3a] "Audio active line signal does not conform to the expected model"

* [@2a] "IO prepare line is not connected correctly"
* [@2b] "IO Pulse inverted line is not connected correctly"
* [@2c] "IO Bridge line is not connected correctly"
* [@2d] "IO Pulse AND IO Pulse inverted line is not connected correctly"
* [@2e] "IO Pulse line is not connected correctly"
* [@2f] "IO Ready line is not connected correctly"

* [@1c] "clock frequency does not match inverse"

Default is @1b, @3a, @2b

## D-pin guesses
	|D2| A5          A1 A0 | @1. likely inverse clock
	|D3|  x  x     x  x    | @1. likely clock
	|D4| A5          A1 A0 | @3a audio active line -- confirmed
	|D5|                A0 | ? pulse inverted?
	|D6|    A4 A3 A2       | @2a IO prepare line -- very likely
	|..|                   |
	|D9|       A3          | ? pulse line
	|DA|    A4 A3 A2       | @2f IO ready line -- very likely
	|DB|                   |
	|DC|                   |
	|DD|                   |

## Active Attempts
A5 A4 A3 A2 A1 A0 AR
               D3 D2:         @3a     @2b
D5 D6 D9    D4 D3 D2:             @2a     @2f
D5    D9    D4 D3 D2:                     @2f
D5 DA D9    D4 D3 D2: The secure hardware interface has been detected.

The @a1 lines suggest 
Trying A0 as inverse clock -> consistently inconsistent, matches LA, deny
Trying A5 as clock -> unexpected frequency
I'm moderately convinced that A4 is the clock line -> D3

Idea:
	A0 / AREF are kinda-inversy -- big? HUGE
	A4 and SCL are very similar

## Todo
	- @1b->@1c: for each A5:A1:A0 that give @1c, try all other pins?
	- I'm seeing clear pin groupings... see how that continues

## Done
	- D5 disrupts the above... that's important... nope, a glitch
	- Ben didn't get much @2b, his default different than mine
	- check if headphone lines affect the issues...
	- test: A5:A2, A0:A3, A1:A3, A4:A3 -> D4:D6
	- test that A0->D3 is important in above
	- scan D3, see if we get anything
	- check if lines are idling high instead being pulled high, etc

## Playing with pull-ups
No obvious effect for either up nor down

Mixing 0+1, 2+3, 4+5 -> low dominates


## The Big Table
A5 A4 A3 A2 A1 A0 AR
               D2   :     @1c @3a     @2b
               D3   : @1b     @3a     @2b
            D2      :     ~1c @3a     @2b
            D2 D3   : @1b     @3a     @2b
            D3      : @1b             @2b
            D3 D2   :     @1c         @2b
         D2         : @1b     @3a     @2b
         D2    D3   : @1b     @3a     @2b
         D2 D3      :     @1c         @2b
         D3         : @1b     @3a     @2b
         D3    D2   :     @1c @3a     @2b
         D3 D2      :     ~1c @3a     @2b
         DA         : @1b     @3a     @2b
      D2            : @1b     @3a     @2b
      D2       D3   : @1b     @3a     @2b
      D2    D3      :     @1c         @2b
      D2 D3         : @1b     @3a     @2b
      D3            : @1b     @3a     @2b
      D3       D2   :     @1c @3a     @2b
      D3    D2      :     @1c @3a     @2b
      D3 D2         : @1b     @3a     @2b
      D6       D4   : @1b             @2b
      D6    D4      : @1b             @2b
      DA            : @1b     @3a     @2b
   D2               : @1b     @3a     @2b
   D2          D3   : ~1b     @3a     @2b
   D2       D3      :     @1c         @2b
   D2    D3         :   @1a   @3a     @2b
   D2 D3            :   @1a   @3a
   D3               : @1b     @3a     @2b
   D3          D2   :     @1c @3a     @2b
   D3       D2      :     @1c @3a     @2b
   D3    D2         : @1b     @3a     @2b
   D3 D2            : @1b     @3a     @2b
   D4    D6         :         @3a     @2b
   D4 D6            : @1b     @3a     @2b
   D6       D4      : ~1b             @2b
   DA               : @1b     @3a     @2b
D2                  :     @1c @3a     @2b
D2             D3   : @1b     @3a     @2b
D2          D3      :   @1a           @2b
D2       D3         :     @1c @3a     @2b
D2    D3            :     ~1c @3a     @2b
D2 D3               :     @1c         @2b
D2 D4    D6    D3   :         @3a     @2b
D2 D6       D4 D3   : ~1b             @2b
D2 D6    D5 D4 D3   : @1b             @2b
D2 D6 D3       D4   :     ~1c @3a     @2b
D2 D6 D3    D4      :     ~1c         @2b
D2 D6 D5    D4 D3   : @1b             @2b
D3                  : @1b             @2b
D3             D2   : @1b             @2b
D3          D2      :   @1a           @2b
D3       D2         :     ~1c         @2b
D3    D2            :   @1a           @2b
D3 D2               :     ~1c         @2b
D3 D2 D6       D4   :     ~1c ~3a     @2b
D3 D2 D6    D4      :     @1c         @2b
D3 D4    D6    D2   : @1b     @3a     @2b
D4             D6   : @1b         @2a @2b
D4          D6      : @1b         @2a @2b
D4       D6         : @1b             @2b
D4       D6    D2   :     @1c         @2b
D4       D6    D3   : @1b             @2b
D4       D6    D5   : @1b             @2b
D4       D6    D9   : @1b             @2b
D4       D6    DA   : @1b             @2b @2f
D4       D6    DB   : @1b             @2b
D4       D6    DC   : @1b             @2b
D4       D6    DD   : @1b             @2b
D4       D6 DA      : @1b             @2b @2f
D4    DA D6         : @1b             @2b
D4 DA    D6         : @1b             @2b
D5    D9            : @1b     @3a
D5    D9    D2      :     ~1c @3a
D5    D9    D2 D3   : @1b     @3a
D5    D9    D3 D2   : @1b
D5    D9 D2 D3      :     @1c
D5    D9 D3    D2   :     @1c @3a
D5    D9 D3 D2      :     @1c @3a
D5    D9 D3 D4      : @1b
D5    D9 D3 D4 D2   :  ~1[bc]
D5 D2 D9       D3   : @1b     @3a
D5 D2 D9    D3      : @1b     @3a
D5 D2 D9 D3         : @1b     @3a
D5 D2 D9 D3 D4      : @1b
D5 D3 D9       D2   :     @1c
D5 D3 D9    D2      :     @1c
D5 D6 D9    D4      :  ~1[ac]
D5 D6 D9    D4 D2   : ~1[bc]
D5 D6 D9 D2 D4      : ~1[ab]
D6 D4               : @1b     @3a @2a @2b
DA                  : @1b     @3a     @2b @2f

## Reading out the code:

3674a755bc3aea31819a83de5ee36810

36748755ec3aea31815883bd5ee36810

I can't resolve to [a8] or [bdce]...
Wait for a better link.
