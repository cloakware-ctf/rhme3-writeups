import idascript

import sys
import os
import traceback

import logging
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler(stream=sys.stdout)
    logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

try:
    import idautils
    import idaapi
    import sark

    print os.path.dirname(__file__)
    sys.path.insert(0, os.path.dirname(__file__))
    from avr_utils import *

    rpairs = avr_get_register_pairs()

    def make_stack_variable(func_start, offset, name, size):
        func = idaapi.get_func(func_start)
        frame = idaapi.get_frame(func)

        offset += func.frsize
        member = idaapi.get_member(frame, offset)

        if member:
            return 0
        else:
            # No member at the offset, create a new one
            if idaapi.add_struc_member(frame,
                    name,
                    offset,
                    idaapi.wordflag() if size == 2 else idaapi.byteflag(),
                    None, size) == 0:
                return 1
            else:
                return 0

    def is_latter_of_sequential_instructions(prev_line, curr_line, op_num):
        if prev_line is None:
            return False

        try:
            curr_insn = curr_line.insn
            prev_insn = prev_line.insn
        except sark.exceptions.SarkNoInstruction:
            return False

        if len(prev_insn.operands) != 2 or len(curr_insn.operands) != 2:
            return False

        other_op_num = 0
        if op_num == 0:
            other_op_num = 1

        if (
            str(prev_insn.operands[op_num]).startswith('Y+') and
            prev_insn.operands[op_num].offset == curr_insn.operands[op_num].offset - 1 and
            prev_insn.operands[other_op_num].reg == rpairs.get(curr_insn.operands[other_op_num].reg)
           ):
            logger.debug("offsets 0x%x && 0x%x + registers %s and %s are sequential: %s && %s" % (prev_insn.operands[op_num].offset, curr_insn.operands[op_num].offset, prev_insn.operands[other_op_num].reg, curr_insn.operands[other_op_num].reg, prev_line, curr_line))
            return True

        return False

    def doesnt_imply_stack_var(curr_insn):
        return str(curr_insn.operands[1].reg) == 'r1'

    def operand_to_stack_variable(curr_line, op_num):
        logger.debug("setting stack var operand %d of %s" % (op_num, curr_line))
        idc.OpStkvar(curr_line.ea, op_num)
        return

    def create_stack_variable_from_operand(curr_line, op_num):
        try:
            curr_insn = curr_line.insn
        except sark.exceptions.SarkNoInstruction:
            return

        if doesnt_imply_stack_var(curr_insn):
            return

        stack_offset = curr_insn.operands[op_num].offset
        this_function = sark.Function(curr_line.ea)

        next_line = sark.Line(curr_line.ea + len(curr_line.bytes))
        size = 2 if is_latter_of_sequential_instructions(curr_line, next_line, op_num) else 1

        logger.info("creating %d byte stack variable @ 0x%x based on %s && %s" % (size, stack_offset, curr_line, next_line))

        make_stack_variable(this_function.startEA, stack_offset, "var_%x" % stack_offset, size)
        return

    def all_y_stack_vars_here():
        ea = idc.here()
        this_function = sark.Function(ea)

        prev = None
        for line in this_function.lines:
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

            if (len(curr_insn.operands) != 2 or
                str(curr_insn.operands[0]) == '' or str(curr_insn.operands[1]) == ''
                ):
                logger.debug("filtering: %s" % (line))
                prev = line
                continue

            logger.debug("testing %s" % (line))

            if str(curr_insn.operands[1]).startswith('Y+'):
                operand_to_stack_variable(line, 1)
                if not is_latter_of_sequential_instructions(prev, line, 1): # avoid marking a stack var for the second part of a sequential load
                    create_stack_variable_from_operand(line, 1)

            if str(curr_insn.operands[0]).startswith('Y+'):
                operand_to_stack_variable(line, 0)
                if not is_latter_of_sequential_instructions(prev, line, 0): # avoid marking a stack var for the second part of a sequential load
                    create_stack_variable_from_operand(line, 0)

            # TODO also for Y+ in operand 0
            prev = line

    print("some utility functions are defined:\nall_y_stack_vars_here()")

except:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

idascript.exit()
