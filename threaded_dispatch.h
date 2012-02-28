/**
 * threaded_dispatch.h
 * Macros for threaded dispatch
 *
 * @author  Edwin Boaz Soenaryo
 * @email   edwinbs@comp.nus.edu.sg
 */

#pragma once

/* Declares op_ptr, which is the lookup table for the opcodes
   Targets are initialized to cannot_emulate */
#define BEGIN_OPCODE_MAP                                                       \
    void* op_ptr[256][8];                                                      \
    {                                                                          \
        size_t _op, _ext;                                                      \
        for(_op=0;_op<256;++_op)                                               \
            for(_ext=0;_ext<8;++_ext)                                          \
                op_ptr[_op][_ext] = &&cannot_emulate;

/* Maps a single opcode and extension to a label */
#define MAP1_EXT(opcode, ext, label, am_flags)                                 \
        op_ptr[(opcode)][ext] = &&label;                                       \
        am[(opcode)] = am_flags;

/* For extension-less opcodes, all valid extensions (0-7)
   are mapped to the label, so whatever reg happens to be, it will be ok. */
#define MAP1(opcode, label, am_flags)                                          \
        for(_ext=0;_ext<8;++_ext) { MAP1_EXT(opcode, _ext, label, am_flags); }
    
/* Maps a range of opcodes to the same label */
#define MAPR(start, end, label, _am_flags)                                     \
        for(_op=start;_op<=end;++_op) { MAP1(_op, label, _am_flags); }

#define END_OPCODE_MAP                                                         \
    }

/* Dispatch code, appended at the end of each instruction's impl
   First few lines are useless, ignore them
   Execution halts when there is no more code to execute
   Otherwise, it will attempt to decode the next opcode
   The check for ctx.reg is necessary for opcodes without MOD_REG_RM byte */
#define DISPATCH_NEXT                                                          \
    print_code(pCode, prev_instr_offset, EMU_EIP - prev_instr_offset);         \
    printf("\t%s\n\n", last_instr_name);                                       \
    prev_instr_offset = EMU_EIP;                                               \
    print_all_registers();                                                     \
    print_stack();                                                             \
	printf("(Press ENTER to step an instruction)");                            \
    getchar();                                                                 \
                                                                               \
	if (EMU_EIP >= nCodeLen) goto halt;                                        \
    eip += decode_instr(pCode + EMU_EIP, &ctx);                                \
	goto *(op_ptr[ctx.opcode][ctx.reg <= 7 ? ctx.reg : 0]);

/* For convenience (and coolness) */
#define INSTR(label)                                                           \
    DISPATCH_NEXT                                                              \
    label:                                                                     \
    last_instr_name = #label;

#define ON_CANNOT_EMULATE   INSTR(cannot_emulate)
#define ON_HALT             INSTR(halt)
