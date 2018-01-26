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

    data_vectors = {
        'r27': 'XH',
        'r26': 'XL',
        'r29': 'YH',
        'r28': 'YL',
        'r31': 'ZH',
        'r30': 'ZL'
    }

    for vector_register in data_vectors.keys():
        register_line = sark.Line(idaapi.get_name_ea(0, vector_register))

        register_line.name = data_vectors.get(vector_register)
        register_line.comments.repeat = "alias:%s" % vector_register

except:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

idascript.exit()
