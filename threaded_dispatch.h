/**
 * threaded_dispatch.h
 * Macros for threaded dispatch
 *
 * @author  Edwin Boaz Soenaryo
 * @email   edwinbs@comp.nus.edu.sg
 */

#pragma once

#define BEGIN_OPCODE_MAP                                                    \
    void* op_ptr[256][8];                                                   \
    {                                                                       \
        size_t _op, _ext;                                                   \
        for(_op=0;_op<256;++_op)                                            \
            for(_ext=0;_ext<8;++_ext)                                       \
                op_ptr[_op][_ext] = &&cannot_emulate;

#define MAP1_EXT(opcode, ext, label, am_flags)                              \
        op_ptr[(opcode)][ext] = &&label;                                    \
        am[(opcode)] = am_flags;
    
#define MAP1(opcode, label, am_flags)                                       \
        for(_ext=0;_ext<8;++_ext) MAP1_EXT(opcode, _ext, label, am_flags);
    
#define MAPR(start, end, label, am_flags)                                   \
        for(_op=start;_op<=end;++_op) MAP1(_op, label, am_flags);

#define END_OPCODE_MAP                                                      \
    }

#define INSTR(label)                                                        \
    print_code(pCode, prev_instr_offset, EMU_EIP - prev_instr_offset);      \
    printf("\t%s\n\n", last_instr_name);                                    \
    prev_instr_offset = EMU_EIP;                                            \
    print_all_registers();                                                  \
    print_stack();                                                          \
    getchar();                                                              \
                                                                            \
	if (EMU_EIP >= nCodeLen) goto halt;                                     \
    eip += decode_instr(pCode + EMU_EIP, &ctx);                             \
	goto *(op_ptr[ctx.opcode][ctx.reg]);                                    \
	                                                                        \
    label:
    
#define ON_CANNOT_EMULATE   INSTR(cannot_emulate)
#define ON_HALT             INSTR(halt)