import idascript

import sys
import os
import traceback

import logging
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler(stream=sys.stdout)
    logger.addHandler(handler)

try:
    import idautils
    import idaapi
    import sark

    def avr_loader_emu(source_start, target_start, target_end):
        ram_segment = None
        rom_segment = None
        for segment in sark.segments():
            if segment.name == 'RAM':
                ram_segment = segment
            elif segment.name == 'ROM':
                rom_segment = segment

        for offset in range(0, target_end-target_start, 2):
            val = Word(rom_segment.startEA + (source_start + offset)/2)
            PatchWord(ram_segment.startEA + target_start + offset, val)

        sark.Line(ram_segment.startEA + target_start).comments.repeat = "DATA start"
        sark.Line(ram_segment.startEA + target_end).comments.repeat = "DATA end"
        return

    def avr_bss_emu(target_start, target_end):
        ram_segment = None
        for segment in sark.segments():
            if segment.name == 'RAM':
                ram_segment = segment

        for offset in range(0, target_end-target_start):
            PatchByte(ram_segment.startEA + target_start + offset, 0)

        sark.Line(ram_segment.startEA + target_start).comments.repeat = "BSS start"
        sark.Line(ram_segment.startEA + target_end).comments.repeat = "BSS end"
        return

except:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

idascript.exit()
