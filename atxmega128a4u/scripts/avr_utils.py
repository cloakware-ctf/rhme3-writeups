import sys
import logging
utils_logger = logging.getLogger(__name__)
if not utils_logger.handlers:
    handler = logging.StreamHandler(stream=sys.stdout)
    utils_logger.addHandler(handler)
utils_logger.setLevel(logging.INFO)

def avr_get_register_pairs():
    rpairs = dict()

    for i in range(1, 33, 2):
        rpairs.update({"r%d" % i: "r%d" % (i-1)})

    rpairs.update({
        'XH': 'XL',
        'YH': 'YL',
        'ZH': 'ZL'
    })

    return rpairs

def is_latter_of_rxN_sequential_instructions(prev_line, curr_line, op_num):
    if prev_line is None:
        return False

    try:
        curr_insn = curr_line.insn
        prev_insn = prev_line.insn
    except sark.exceptions.SarkNoInstruction:
        return False

    if (len(prev_insn.operands) != 2 or len(curr_insn.operands) != 2 or
        str(prev_insn.operands[0]) == '' or str(prev_insn.operands[1]) == '' or str(curr_insn.operands[0]) == '' or str(curr_insn.operands[1]) == '' or
        str(prev_insn.operands[op_num].type) != 'General_Register' or str(curr_insn.operands[op_num].type) != 'General_Register'
       ):
        return False

    if prev_insn.operands[op_num].reg == avr_get_register_pairs().get(curr_insn.operands[op_num].reg):
        utils_logger.debug("registers %s and %s are sequential: %s && %s" % (prev_insn.operands[op_num].reg, curr_insn.operands[op_num].reg, prev_line, curr_line))
        return True

    return False
