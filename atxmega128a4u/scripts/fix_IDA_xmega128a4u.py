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

base_dir = os.path.dirname(__file__) #nice, but only works in idascript command-line, not in runscript() calls
xmega128a4u_def = os.path.join(base_dir, '..', 'resources', 'ATxmega128A4U.atdf')

try:
    import idautils
    import idaapi
    import sark
    import xml.etree.ElementTree as et

    tree = et.parse(xmega128a4u_def)
    root = tree.getroot()

    r0_address = idaapi.get_name_ea(0, 'r0')

    all_bases = dict()
    for register_group in root.findall(".//peripherals/module/instance/register-group[@address-space='data']"):
        base = int(register_group.attrib['offset'], 0)
        if all_bases.get("%04x" % base) is None:
            all_bases.update({"%04x" % base: register_group})

    for key in sorted(all_bases.keys()):
        register_group = all_bases.get(key)
        base_name = register_group.attrib['name']
        name_in_module = register_group.attrib['name-in-module']
        base = int(register_group.attrib['offset'], 0)
        for register in root.findall(".//modules/module/register-group[@name='%s']/register" % name_in_module):
            name = register.attrib['name']
            offset = int(register.attrib['offset'], 0)
            caption = register.attrib['caption']

            ioport_name = "%s_%s" % (base_name, name)

            #the ATxmega128a4u doens't have a register file mapped at 0x0 in RAM which is being forced by the avr IDA module; correct the location of all the mapped IO ports

            wrong_line = sark.Line(idaapi.get_name_ea(0, ioport_name))
            right_line = sark.Line(wrong_line.ea - 0x20)
            wrong_line.name = ""
            wrong_line.comments.repeat = ""

            offset = right_line.ea - r0_address

            #actually renaming the data locations in the first 0x20 will make IDA disassembly look bonkers because it uses the names of those data locations for its register names
            #just append a comment about the ioport location in question to the first 0x20
            if offset <= 0x20:
                previous_comment = right_line.comments.repeat
                ioport_comment = "io:%s" % ioport_name
                if previous_comment is None:
                    right_line.comments.repeat = ioport_comment
                else:
                    right_line.comments.repeat = previous_comment + " " + ioport_comment
            else:
                right_line.name = ioport_name
                right_line.comments.repeat = caption

except:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

idascript.exit()
