RHME3 Challenge Files

Challenge binaries, hex, IDBs in one-directory-per-challenge:

```
ransom/
ransom_2.0/
can_opener/
unauthorized/
car_crash/
full_compromise/
... etc
```

Some support files for the target processor ATXMEGA128A4U:

```
atxmega128a4u/
  atpack/    -- xml defs for all the targets in the family
  doc/       -- docs for our target
  lib/       -- some libc's for the target
  resources/ -- xml defs, header files, asm includes IDA cfg files for the target
  samples/   -- samples of builds for the target
  scripts/   -- lots of IDAPython scripts for setting up .idb files of ATXMEGA128A4U firmwares
```

Some support files for other Atmel MEGA processors:

```
other_atmega/ -- similar structure to above
```

... and some reversing notes (don't read these unless you want to be sad): ```reversing-notes.md```
