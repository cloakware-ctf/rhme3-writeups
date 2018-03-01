
## Challenge
You have a basic car model and would like to enable some extra features? That navigation with traffic should be neat. Right. It is expensive, you know. Or not, if you can access the control interface. Try bluetooth this time. We think, it could be used for purposes other than making calls and playing MP3s.

## Initial Analysis
Loop 1: X <- Z
	X = 0x2000 .. 0x2190
	Z = 0x2dd0
Loop 2: X <- 0
	X = 0x2190 .. 0x2261

Hmmmmmm.... strcpy.... strlen... this will be fun.


