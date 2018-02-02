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

# just try the dumb thing and make xrefs based on seq load of pairs of immediates.
# doesn't consider RAMP% register values, doesn't consider anything more complicated than:
# ld r(X-1), #imm
# ld rX, #imm

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

    rpairs = dict()

    for i in range(1,33):
        rpairs.update({"r%d" % i: "r%d" % (i-1)})

    rpairs.update({
        'XL': 'r25',
        'YL': 'XH',
        'ZL': 'YH',

        'XH': 'XL',
        'YH': 'YL',
        'ZH': 'ZL'
    })

    prev = None
    for line in sark.lines(rom_segment.startEA, rom_segment.endEA):
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
            str(prev_insn.operands[0]) == '' or str(prev_insn.operands[1]) == '' or str(curr_insn.operands[0]) == '' or str(curr_insn.operands[1]) == '' or
            str(prev_insn.operands[0].type) != 'General_Register' or str(curr_insn.operands[0].type) != 'General_Register' or
            str(prev_insn.operands[1].type) != 'Immediate_Value' or str(curr_insn.operands[1].type) != 'Immediate_Value'
            ):
            logger.debug("filtering: %s && %s" % (prev, line))

            if curr_insn.mnem == 'ldi' and prev_insn.mnem == 'ldi':
                logger.warning("false filtered %s && %s\n\t%s %s %s\n\t%s %s %s" % (prev, line, len(prev_insn.operands), prev_insn.operands[0].type, prev_insn.operands[1].type, len(curr_insn.operands), curr_insn.operands[0].type, curr_insn.operands[1].type))

            prev = line
            continue

        def safe_name(address):
            name = sark.Line(address).name
            if name[0:4] == 'unk_':
                 return "0x%x" % address
            else:
                return  "%s" % name

        logger.debug("testing @ 0x%x %s == %s" % (line.ea, prev_insn.operands[0].reg, rpairs.get(curr_insn.operands[0].reg)))
        if prev_insn.operands[0].reg == rpairs.get(curr_insn.operands[0].reg):
                word = int(curr_insn.operands[1].text, 0) * 256 + int(prev_insn.operands[1].text, 0)
                address = ram_segment.startEA + word

                if address <= ram_segment.endEA:
                    result = add_dref(line.ea, address, dr_T)
                    logger.debug("add dref from 0x%x to 0x%x: %s" % (line.ea, address, str(result)))
                    line.comments.repeat = safe_name(address)

        prev = line

        def dref_range_fixer(startEA, endEA):
            for line in sark.lines(startEA, endEA):
                for xref in line.xrefs_to:
                    if xref.iscode or xref.frm == idc.BADADDR or str(xref.type) != 'Data_Text': # only try to fix data references from code in ROM of the Data_Text type (as created by the dumb seq xref routine above)
                        continue
                    logger.debug("fixing xref (type:%s) to %s from 0x%x" % (xref.type, safe_name(line.ea), xref.frm))
                    sark.Line(xref.frm).comments.repeat = safe_name(line.ea)
            return

        def dref_fixer():
            dref_range_fixer(SelStart(), SelEnd())
            return

        def dref_all_fixer():
            dref_range_fixer(ram_segment.startEA, ram_segment.endEA)
            return

    print("data xrefs (drefs) added for all sequential loads of the bytes 16-bit addresses into RAM.\nIf any lines are renamed in the RAM segment, then the drefs can be fixed by running dref_fixer() on a selection of ram addresses or dref_all_fixer() to perform this operation over all of the RAM segment.")

except:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

idascript.exit()
