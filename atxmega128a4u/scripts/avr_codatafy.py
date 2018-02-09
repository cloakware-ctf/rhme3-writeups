import idascript

import sys
import os
import traceback

import logging
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler(stream=sys.stdout)
    logger.addHandler(handler)
logger.setLevel(logging.WARNING)

try:
    import idautils
    import idaapi
    import sark

    ram_segment = None
    rom_segment = None
    for segment in sark.segments():
        if segment.name == 'RAM' or segment.name == '.data':
            ram_segment = segment
        elif segment.name == 'ROM' or segment.name == '.text':
            rom_segment = segment

    #stringify
    print("Looking for possible strings in %s segment..." % (idc.SegName(ram_segment.startEA)))

    counter = 0
    for s in idautils.Strings():
        if s.ea >= ram_segment.startEA and s.ea < ram_segment.endEA:
            if not idc.isASCII(idc.GetFlags(s.ea)) and idc.MakeStr(s.ea, idc.BADADDR):
                counter += 1
    print "created %d new ASCII strings" % counter


    #datify
    print "Converting remaining data in RAM to words..."

    for line in sark.lines(ram_segment.startEA, ram_segment.endEA):
        flags = idc.GetFlags(line.ea)

        if (idc.isUnknown(flags) or idc.isByte(flags)) and line.ea % 2 == 0:
            idc.MakeWord(line.ea)

            val = Word(line.ea)
            if val > 31: #ignore data references to small values (like r0-r31)
                idc.OpOff(line.ea, 0, ram_segment.startEA)

    print "all lines in 0x%x - 0x%x are now words" % (ram_segment.startEA, ram_segment.endEA)

    #pointify
    print "looking for off_{} to rename to {}_ptr"
    counter = 0
    for (name_ea, name) in idautils.Names():
        logger.debug("looking for off_ %s @ 0x%x" % (name, name_ea))
        Wait()
        for xref in sark.Line(name_ea).xrefs_to:
            logger.debug("considering xref to %s at 0x%x" % (name, xref.frm))
            original_name = sark.Line(xref.frm).name
            if original_name.startswith("off_"):
                i = 0
                pointer_name = name + "_ptr"
                while sark.Line(name=pointer_name).ea != idc.BADADDR:
                    pointer_name = name + "_ptr%d" % i
                    i += 1

                sark.Line(xref.frm).name = pointer_name
                logger.debug("renamed %s to %s" % (name, pointer_name))
                counter += 1

    print "renamed %d pointers" % counter

except:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

idascript.exit()
