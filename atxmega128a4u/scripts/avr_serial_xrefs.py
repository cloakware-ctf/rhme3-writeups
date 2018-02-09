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

    for (name_ea, name) in idautils.Names():
        if not name.startswith("USART"):
            continue
        logger.debug("looking for xrefs to %s @ 0x%x" % (name, name_ea))
        Wait()
        for xref in sark.Line(name_ea).xrefs_to:
            print "%s <-- 0x%x" %(name, xref.frm)


except:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

idascript.exit()
