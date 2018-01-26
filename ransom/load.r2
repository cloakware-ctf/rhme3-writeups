
# TODO initialize esil vm
#e esil.stack.addr = 0x20000000
#e esil.stack.size = 0x000f0000

#e asm.section.sub = true

#S ${esil.stack.addr} ${esil.stack.addr} ${esil.stack.size} ${esil.stack.size} ram mrwx
aeim

# allocate RAM areas (not in ihex)

#mapped ioports
on malloc://1K 0x0000
S 0x0000 0x0000 1K 1K fsr mrw-

#mapped eeprom
on malloc://2K 0x1000
S 0x1000 0x1000 2K 2K eeprom mrw-

#internal sram
on malloc://16K 0x2000
S 0x2000 0x2000 16K 16K iram mrw-

# some settings
e asm.describe=true
e asm.midflags=true
e asm.emu=true

# configure the CPU for the project
e asm.arch = avr
e asm.cpu = ATmega328p
e asm.bits = 8

# load ihex into program address space 
on jailbreak.bin boot
e io.va = true
e anal.hasnext = true
# e io.sectonly = true
S boot boot $s $s boot mrwx
Sa arm 16 boot

# run analysis on bootloader
s boot
e search.in = io.sections.exec
aac
?E Functions found `afl~?` in the bootloader
# aav

?e ========================

# load the decrypted system image
#e bin.baddr = 0x8000c000
f system=0x8000c000
on newfw.bin system
e io.va = true
e asm.arch = arm
e asm.bits = 16
e anal.hasnext = true
# e io.sectonly = true
e search.in = io.sections.exec
# 0x2001d39b
S 0 system $s $s firmware mrwx
Sa arm 16 system
s system

#aac
?E This is the 1MB firmware
#aav
.S*
