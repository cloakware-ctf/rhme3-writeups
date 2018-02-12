import idascript

import sys
import os
import traceback

import logging
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler(stream=sys.stdout)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# just try the dumb thing and make xrefs based on seq load of pairs of immediates.
# doesn't consider RAMP% register values, doesn't consider anything more complicated than:
# ld r(X-1), #imm
# ld rX, #imm

try:
    import idautils
    import idaapi
    import sark

    print os.path.dirname(__file__)
    sys.path.insert(0, os.path.dirname(__file__))
    from avr_utils import *

    ram_segment = None
    rom_segment = None
    for segment in sark.segments():
        if segment.name == 'RAM' or segment.name == '.data':
            ram_segment = segment
        elif segment.name == 'ROM' or segment.name == '.text':
            rom_segment = segment

    def safe_name(address):
        name = sark.Line(address).name
        if name[0:4] == 'unk_':
             return "0x%x" % address
        else:
            return  "%s" % name

    def dref_range_fixer(startEA, endEA):
        for line in sark.lines(startEA, endEA):
            for xref in line.xrefs_to:
                if xref.iscode or xref.frm == idc.BADADDR or str(xref.type) != 'Data_Text': # only try to fix data references from code in ROM of the Data_Text type (as created by the dumb seq xref routine above)
                    continue
                logger.debug("fixing xref (type:%s) to %s from ROM:%x" % (xref.type, safe_name(line.ea), xref.frm))
                sark.Line(xref.frm).comments.repeat = str(sark.Line(xref.frm).comments.repeat).replace("0x%x" % line.ea, safe_name(line.ea))
        return

    def dref_fixer():
        dref_range_fixer(SelStart(), SelEnd())
        return

    def dref_all_fixer():
        dref_range_fixer(ram_segment.startEA, ram_segment.endEA)
        return

    def avr_dumb_seq_load_xrefs(startEA, endEA):
        prev = None
        for line in sark.lines(startEA, endEA):
            if prev is None:
                prev = line
                continue

            try:
                curr_insn = line.insn
                prev_insn = prev.insn
            except sark.exceptions.SarkNoInstruction:
                logger.debug("skipping @ 0x%x" % line.ea)
                prev = line
                continue

            if (len(prev_insn.operands) != 2 or len(curr_insn.operands) != 2 or
                str(prev_insn.operands[1]) == '' or str(curr_insn.operands[1]) == ''
                ):
                logger.debug("filtering: %s && %s" % (prev, line))
                prev = line
                continue

            logger.debug("testing %s && %s" % (prev, line))
            if (is_latter_of_rxN_sequential_instructions(prev, line, 0) and
                str(prev_insn.operands[1].type) == 'Immediate_Value' and str(curr_insn.operands[1].type) == 'Immediate_Value'
               ):
                idc.OpHex(prev.ea, 1)
                idc.OpHex(line.ea, 1)
                if prev_insn.mnem == 'subi' and curr_insn.mnem == 'sbci':
                    word = (int(curr_insn.operands[1].text, 0) + 1) * -256 + int(prev_insn.operands[1].text, 0) * -1
                    address = ram_segment.startEA + word

                    if (address > ram_segment.startEA + 0x2000 and address < ram_segment.endEA and
                        str(prev_insn.operands[0]) != 'YL' and str(prev_insn.operands[0].reg) != 'r28' # ignore indexed access into stack
                       ):
                        result = add_dref(line.ea, address, dr_T)
                        logger.info("%s adding dref to %s at ROM:%x \"%s\"" % ("Success" if result else "Error", safe_name(address), line.ea, line))
                        line.comments.repeat = "indexed access into %s" % safe_name(address)
                else:
                    word = int(curr_insn.operands[1].text, 0) * 256 + int(prev_insn.operands[1].text, 0)
                    address = ram_segment.startEA + word

                    if address >= ram_segment.startEA and address < ram_segment.endEA:
                        result = add_dref(line.ea, address, dr_T)
                        logger.info("%s adding dref to %s at ROM:%x \"%s\"" % ("Success" if result else "Error", safe_name(address), line.ea, line))
                        if address <= ram_segment.startEA + 32:
                            line.comments.repeat = "possible %s" % sark.Line(address).comments.repeat # use the ioport name in the comments
                        else:
                            line.comments.repeat = safe_name(address)

            prev = line

    def all_avr_dumb_seq_load_xrefs():
        avr_dumb_seq_load_xrefs(rom_segment.startEA, rom_segment.endEA)
        return

    def all_avr_dumb_seq_load_xrefs_here():
        this_function = sark.Function(idc.here())
        avr_dumb_seq_load_xrefs(this_function.startEA, this_function.endEA)
        return

    print("some utility functions are defined. run\nall_avr_dumb_seq_load_xrefs() to define data xrefs (drefs) for all sequential loads of the bytes 16-bit addresses into RAM throughout the whole binary,\nall_avr_dumb_seq_load_xrefs_here() for the current function and\navr_dumb_seq_load_xrefs(startEA, endEA) for a custom range\nIf any lines are renamed in the RAM segment, then the drefs can be fixed by running dref_fixer() on a selection of ram addresses or dref_all_fixer() to perform this operation over all of the RAM segment.")

except:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

idascript.exit()
