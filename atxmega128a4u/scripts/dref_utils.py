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

    def safe_name(address):
        name = sark.Line(address).name
        if name[0:4] == 'unk_':
             return "0x%x" % address
        else:
            return  "%s" % name

    def add_dref_named_offset(name, offset):
        here = idc.here()
        there = sark.Line(name=name).ea
        result = add_dref(here, there + offset, dr_T)
        logger.debug("add dref from 0x%x to 0x%x: %s" % (here, there + offset, str(result)))
        sark.Line(here).comments.repeat = safe_name(there + offset)
        return

    def del_dref_named_offset(name, offset):
        here = idc.here()
        there = sark.Line(name=name).ea
        result = del_dref(here, there + offset)
        logger.debug("del dref from 0x%x to 0x%x: %s" % (here, there + offset, str(result)))
        sark.Line(here).comments.repeat = ''
        return

    print("some utility functions are defined:\nadd_dref_named_offset(name, offset)\ndel_dref_named_offset(name, offset)")

except:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

idascript.exit()
