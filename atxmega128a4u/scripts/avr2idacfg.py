#!/usr/bin/env python3
#########################################################################################################
# Based on avrread utility                                                                              #
#                        by Cliff Lawson                                                                #
# His license:                                                                                          #
# Licence: I need beer - see what you can do!                                                           #
#########################################################################################################

#########################################################################################################
# Modified to take an atdf and emit a customized IDA Pro cfg file. ben.gardiner@irdeto.com              #
#########################################################################################################

# following ("from...") line is useful if you are trying to make Python 3 code run in Python 2
# (however things like "argparse" here means this program is 3.2+ anyway.
# from __future__ import print_function
import sys
import os
import argparse
import xml.etree.ElementTree as et
from collections import namedtuple
import ipdb

def info(type, value, tb):
    ipdb.pm()

sys.excepthook = info

parser = argparse.ArgumentParser(description='Read Atmel XML (version 1.3)')
parser.add_argument("-i", "--input", dest='in_fname', help="name of .XML file to read as input")
parser.add_argument("-o", "--output", dest='out_name', help="Name of output file (overides default)")
parser.add_argument("-q", "--quiet", dest='quiet', action="store_true", help="Don't print to console")
parser.add_argument("-v", "--verbose", dest='verbose', action="store_true", help="Show developer info")

# my one argument with argparse is that if you run the app without args it doesn't show help info, so
# this will achieve that...
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

# this actually runs the argument parser on sys.argv
args = parser.parse_args()

flist = []

if args.in_fname is not None and os.path.isfile(args.in_fname):
    flist.append(args.in_fname)

if len(flist) >= 1:
    for fname in flist:

        # Assuming the user has given a name then do our thing!
        if fname is not None and os.path.isfile(fname):
            # the user has the opportunity to use -o to set an output filename but if they haven't used that this
            # takes the input .atdf/.xml filename and replaces the extension with ".h" to create the output name
            if args.out_name is None:
                out_name = os.path.splitext(fname)[0]+".cfg"

            # ===================================== PART 1 (process the XML) ======================================
            # following two lines are the classic way to invoke ElementTree to read an XML then get access to the
            # root from which access to all other data then occurs
            tree = et.parse(fname)
            root = tree.getroot()

            hdr = open(out_name, "wt")

            hdr.write(".%s\n" % os.path.splitext(os.path.basename(fname))[0])
            hdr.write("\n")

            arch = root.find(".//device").attrib['architecture']
            hdr.write("SUBARCH=107 ; should be %s -- 107 is highest supported\n" % arch)

            hdr.write("\n")

            rom_size=int(root.find(".//address-space[@id='prog']").attrib['size'], 0)
            hdr.write("ROM=%s\n" % rom_size)

            ram_size=int(root.find(".//address-space[@id='data']").attrib['size'], 0)
            hdr.write("ROM=%s\n" % ram_size)

            eeprom_size=int(root.find(".//address-space[@id='eeprom']").attrib['size'], 0)
            hdr.write("EEPROM=%s\n" % eeprom_size)

            hdr.write("\n")

            for memory_segment in root.findall(".//address-space[@id='data']/memory-segment"):
                start = int(memory_segment.attrib['start'], 0)
                end = start + int(memory_segment.attrib['size'], 0)
                hdr.write("area DATA %s %s:%s\n" % (memory_segment.attrib['name'], hex(start), hex(end)))

            hdr.write("\n")

            hdr.write("; Interrupt and reset vector assignments\n")
            hdr.write("entry\t%s\t0x%04x\t%s\n" % ('RESET_', 0, 'External Pin, Power-on Reset, Brown-out Reset, Watchdog Reset, and JTAG AVR Reset'))
            for interrupt_group in root.findall(".//interrupts/interrupt-group"):
                base = int(interrupt_group.attrib['index'], 0) * 2
                group_name = interrupt_group.attrib['name-in-module']
                for interrupt in root.findall(".//interrupt-group[@name='%s']/interrupt" % group_name):
                    name = interrupt.attrib['name']
                    offset = int(interrupt.attrib['index'], 0) * 2
                    caption = interrupt.attrib['caption']

                    hdr.write("entry\t%s_\t0x%04x\t%s\n" % (name, base + offset, caption))

            hdr.write("\n")

            hdr.write("; INPUT/OUTPUT PORTS\n")
            for register_group in root.findall(".//peripherals/module/instance/register-group[@address-space='data']"):
                base_name = register_group.attrib['name']
                name_in_module = register_group.attrib['name-in-module']
                base = int(register_group.attrib['offset'], 0)
                for register in root.findall(".//modules/module/register-group[@name='%s']/register" % name_in_module):
                    name = register.attrib['name']
                    offset = int(register.attrib['offset'], 0)
                    caption = register.attrib['caption']

                    hdr.write("%s_%s\t0x%04x\t%s\n" % (base_name, name, base + offset, caption))

                    for bitfield in root.findall(".//modules/module/register-group[@name='%s']/register[@name='%s']/bitfield" % (name_in_module, name)):
                        bitfield_name = bitfield.attrib['name']
                        bitfield_caption = bitfield.attrib['caption']
                        mask = int(bitfield.attrib['mask'], 0)
                        for bit in range(0, 8):
                            if 1 << bit == mask:
                                hdr.write("%s_%s.%s\t%s\t%s\n" % (base_name, name, bitfield_name, bit, bitfield_caption))

                hdr.write("\n")
            hdr.close()
        else:
            print("No valid input file")
