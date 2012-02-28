/**
 * x86emu.c
 * A partial x86 emulator for CS6270
 *
 * The design of this emulator can only handle 1-byte opcodes.
 * For memory, it only emulates registers and the stack.
 *
 * @author  Edwin Boaz Soenaryo
 * @email   edwinbs@comp.nus.edu.sg
 */

#include "registers.h"
#include "threaded_dispatch.h"

#include <stdlib.h>
#include <stdio.h>


#define MAX_CODE_LEN 1024

/* Flags to indicate addressing modes */
#define SRC_IMM_BYTE    (1<<0)  /* Immediate 8-bit operand */
#define EXTENSION       (1<<1)	/* REG in MOD_REG_RM refers to opcode ext */
#define MODRM           (1<<2)	/* There is a MOD_REG_RM byte */
#define SRC_IMM_LONG    (1<<3)  /* Immediate double word operand */
#define REG_ALT_ENC     (1<<4)  /* Register encoded as 3 LSbits of opcode */

/* Addressing mode description for instructions with one-byte opcode */
uint32_t am[256] = { 0 };
#define AM(flag) (am[pCtx->opcode] & flag)

/* 1KB of stack */
/* This underlying stack grows upwards, while the emulated grows downwards */
/* The macro EMU_ESP handles the translation */
uint8_t stack[1024] = { 0 };

/* Execution context of the current instruction */
/* Depending on the instruction, only some fields will be used each time */
typedef struct
{
    uint8_t     opcode;		/* 1-byte opcode */
    unsigned long    ea;	/* effective address from MOD_REG_RM byte */
    uint8_t     mod;		/* MOD part of the MOD_REG_RM byte */
    uint8_t     reg;		/* REG part of the MOD_REG_RM byte */
    uint8_t     rm;			/* RM part of the MOD_REG_RM byte */
    int8_t      immed;		/* 1-byte immediate operand */
    int32_t     immed_l;    /* double word immediate operand */
    uint8_t     eff_reg;    /* register index that will be used */
    int8_t      disp_bits;  /* number of displacement bits */
} context_s;

#define PRINTREG(name, val) printf("%s\t0x%x\n", name, val)

/**
 * \brief	Prints all registers
 */
inline void print_all_registers()
{
    printf("REGISTERS\n");
    PRINTREG("eax", gpr[EAX]);
    PRINTREG("ecx", gpr[ECX]);
    PRINTREG("edx", gpr[EDX]);
    PRINTREG("ebx", gpr[EBX]);
    PRINTREG("esp", gpr[ESP]);
    PRINTREG("ebp", gpr[EBP]);
    PRINTREG("esi", gpr[ESI]);
    PRINTREG("edi", gpr[EDI]);
    PRINTREG("eip", eip);
    PRINTREG("eflags", eflags);
    PRINTREG("cs", cs);
    PRINTREG("ss", ss);
    PRINTREG("ds", ds);
    PRINTREG("es", es);
    PRINTREG("fs", fs);
    PRINTREG("gs", gs);
    printf("\n");
}

/**
 * \brief	Prints the emulated stack from the base decreasing to the ESP
 */
inline void print_stack()
{
    printf("STACK\n");
    uint32_t i = 0;
    for (i = 0; i <= EMU_ESP; ++i)
    {
        printf("0x%08x:\t0x%02x %s\n",
            (BASE_ESP-i), stack[i], (i==EMU_ESP?"<- esp":""));
    }
    printf("\n");
}

/**
 * \brief   Loads up to 1KB of code from the given file. Allocates memory.
 * \param   filename    [in]  file name string
 * \param   ppCode      [out] pointer to return the allocated buffer
 * \param   pnCodeLen   [out] pointer to return the length of allocated buffer
 * \return  0 if successful, -1 if file cannot be opened, -2 if out of memory
 */ 
int load_code(char* filename, unsigned char** ppCode, size_t* pnCodeLen)
{
    FILE* pFile = fopen(filename, "r");
    if (!pFile)
        return -1;
    
    unsigned char* pCode = (char*) malloc(sizeof(char) * MAX_CODE_LEN);
    if (!pCode)
        return -2;
    
    size_t i = 0;
    int hexDigit = 0;
    while (i < MAX_CODE_LEN && fscanf(pFile, "%02x", &hexDigit) != EOF)
        pCode[i++] = (unsigned char) hexDigit;
    
    fclose(pFile);
    
    *ppCode = pCode;
    *pnCodeLen = i;
    
    return 0;
}

/**
 * \brief   Prints the given code in hex, starting at offset,
 *          for the given number of bytes.
 * \param   pCode   [in]  pointer to the code
 * \param   nOffset [in]  starting offset
 * \param   nCount  [in]  number of bytes to print
 */
void print_code(unsigned char* pCode, size_t nOffset, size_t nCount)
{
    size_t i = 0;
    for (i = 0; i < nCount; ++i)
        printf("%02x ", pCode[nOffset + i]);
}

/**
 * \brief   Initializes the registers
 */
void init_registers()
{
    gpr[EAX]    = 0xbf8db144;
    gpr[ECX]    = 0x88c5ffb;
    gpr[EDX]    = 0x1;
    gpr[EBX]    = 0xae5ff4;
    gpr[ESP]    = BASE_ESP;
    gpr[EBP]    = 0xbf8db118;
    gpr[ESI]    = 0x9a0ca0;
    gpr[EDI]    = 0x0;
    
    eip         = BASE_EIP;
    eflags      = 0x246;

    cs          = 0x73;
    ss          = 0x7b;
    ds          = 0x7b;
    es          = 0x7b;
    fs          = 0x0;
    gs          = 0x33;
    
    gprbyte[AL] = LO_OF(EAX);
    gprbyte[CL] = LO_OF(ECX);
    gprbyte[DL] = LO_OF(EDX);
    gprbyte[BL] = LO_OF(EBX);
    gprbyte[AH] = HI_OF(EAX);
    gprbyte[CH] = HI_OF(ECX);
    gprbyte[DH] = HI_OF(EDX);
    gprbyte[BH] = HI_OF(EBX);
}

/**
 * \brief   Decodes the given SIB byte
 * \param   pSIBByte    [in]  pointer to the SIB byte
 * \param   pCtx        [out] pointer to current execution context
 */
inline void decode_sib(unsigned char* pSIBByte, context_s* pCtx)
{
    uint8_t ss      = (*pSIBByte       ) >> 5;
    uint8_t index   = (*pSIBByte & 0x38) >> 2;
    uint8_t base    = (*pSIBByte & 0x07);
    
    switch (base)
    {
        case 0: pCtx->ea = gpr[EAX]; break;
        case 1: pCtx->ea = gpr[ECX]; break;
        case 2: pCtx->ea = gpr[EDX]; break;
        case 3: pCtx->ea = gpr[EBX]; break;
        case 4: pCtx->ea = gpr[ESP]; break;
        case 5:
            if (pCtx->mod == 0x0)
            {
                pCtx->ea = 0x0;
                pCtx->disp_bits = 32;
            }
            else if (pCtx->mod == 0x1)
            {
                pCtx->ea = gpr[EBP];
                pCtx->disp_bits = 8;
            }
            else if (pCtx-> mod == 0x2)
            {
                pCtx->ea = gpr[EBP];
                pCtx->disp_bits = 32;
            }
            break;
        case 6: pCtx->ea = gpr[ESI]; break;
        case 7: pCtx->ea = gpr[EDI]; break;
    }
    
    uint8_t index_val = 0;
    switch (index)
    {
        case 0: index_val = gpr[EAX]; break;
        case 1: index_val = gpr[ECX]; break;
        case 2: index_val = gpr[EDX]; break;
        case 3: index_val = gpr[EBX]; break;
        case 4: index_val = 0; break;
        case 5: index_val = gpr[EBP]; break;
        case 6: index_val = gpr[ESI]; break;
        case 7: index_val = gpr[EDI]; break;
    }
    
    switch (ss)
    {
        case 1: index_val *= 2; break;
        case 2: index_val *= 4; break;
        case 3: index_val *= 8; break;
    }
    
    pCtx->ea += index_val;
}

/**
 * \brief   Decodes the given MOD_REG_RM byte, up to SIB and displacement if
 *          the MOD_REG_RM byte indicates their presence.
 * \param   pModRMByte  [in]  pointer to the MOD_REG_RM byte
 * \param   pCtx        [out] pointer to current execution context
 * \return  number of bytes consumed
 */
inline size_t decode_regrm(unsigned char* pModRMByte, context_s* pCtx)
{
    size_t  pos = 0;
    uint8_t bSIB = 0;
    
    pCtx->mod = (*pModRMByte       ) >> 6;
    pCtx->reg = (*pModRMByte & 0x38) >> 3;
    pCtx->rm  = (*pModRMByte & 0x07);
    
    if (pCtx->mod == 0 || pCtx->mod == 1 || pCtx->mod == 2)
    {
        switch (pCtx->rm)
        {
            case 0: pCtx->ea = gpr[EAX]; break;
            case 1: pCtx->ea = gpr[ECX]; break;
            case 2: pCtx->ea = gpr[EDX]; break;
            case 3: pCtx->ea = gpr[EBX]; break;
            case 4: bSIB = 1; break;
            case 5: pCtx->ea = (pCtx->mod == 0x0) ? 0x0 : gpr[EBP]; break;
            case 6: pCtx->ea = gpr[ESI]; break;
            case 7: pCtx->ea = gpr[EDI]; break;
        }
    }
    else /* pCtx->mod == 3 */
    {
        pCtx->ea = (unsigned long) &(gpr[pCtx->rm]);
    }
    
    /* Determine if there is a displacement byte/dword */
    if (pCtx->mod == 0x1 || (pCtx->mod == 0x0 && pCtx->rm == 0x5))
        pCtx->disp_bits = 8;
    else if (pCtx->mod == 0x2)
        pCtx->disp_bits = 32;
    else
        pCtx->disp_bits = 0;
    
    ++pos; /* ModR/M Byte has been processed */
    
    if (bSIB)
    {
        decode_sib(pModRMByte + 1, pCtx);
        ++pos;
    }
    
    if (pCtx->disp_bits == 8)
    {
        int8_t disp8 = (int8_t) *(pModRMByte + pos);
        pCtx->ea += disp8;
        ++pos;
    }
    else if (pCtx->disp_bits == 32)
    {
        int32_t disp32 = *((int32_t *) (pModRMByte + pos));
        pCtx->ea += disp32;
        pos += 4;
    }
    return pos;
}

/**
 * \brief   Decodes one instruction starting at the pointed code
 * \param   pCode   [in]  pointer to the first byte of instruction to be decoded
 * \param   pCtx    [out] pointer to the current execution context
 * \return  number of bytes consumed
 */
inline size_t decode_instr(unsigned char* pCode, context_s* pCtx)
{
    size_t pos = 0;
    
    pCtx->opcode = *pCode;
    ++pos;
    
    if (AM(MODRM))
    {
        pos += decode_regrm(pCode + pos, pCtx);
        
        if (AM(EXTENSION))
            pCtx->eff_reg = pCtx->rm;
        else
            pCtx->eff_reg = pCtx->reg;
    }
    
    if (AM(SRC_IMM_BYTE))
    {
        pCtx->immed = (int8_t) *(pCode + pos);
        ++pos;
    }
    
    if (AM(SRC_IMM_LONG))
    {
        pCtx->immed_l = *((int32_t*) (pCode + pos));
        pos += 4;
    }
    
    if (AM(REG_ALT_ENC))
    {
        pCtx->eff_reg = (pCtx->opcode) & 0x07;
    }
    
    return pos;
}

/**
 * \brief   Sets the given flags
 * \param   mask    [in]  bits representing the flags to set
 */
inline void set_flags(uint32_t mask)
{
    eflags |= mask;
}

/**
 * \brief   Clears the given flags
 * \param   mask    [in]  bits representing the flags to clear
 */
inline void clear_flags(uint32_t mask)
{
    eflags &= (~mask);
}

/* Checks if an integer is negative in 2's complement representation */
#define IS_NEGATIVE(x) ((x) & 0x80000000)

/**
 * \brief   Modifies the required flags based on the result of last operation.
 *          For OF, the operation is assumed to be ADD,
 *              if it is SUB then the given operand must be negated.
 *          Operands are only required if OF is chosen.
 * \param   mask    [in]  bits representing the flags to be modified
 * \param   result  [in]  result of the last operation
 * \param   op1     [in]  first operand of the last operation
 * \param   op2     [in]  second operand of the last operation
 */
inline void modify_flags(uint32_t mask, int32_t res, int32_t op1, int32_t op2)
{
    /* Parity Flag: Set iff the no of set bits in LSB is even. */
    if (mask & EFLAGS_PF)
    {
        if (__builtin_popcount(res & 0x000000ff) % 2)
            clear_flags(EFLAGS_PF);
        else
            set_flags(EFLAGS_PF);
    }
        
    /* Zero Flag: set iff zero. */
    if (mask & EFLAGS_ZF)
    {
        if (res)
            clear_flags(EFLAGS_ZF);
        else
            set_flags(EFLAGS_ZF);
    }
        
    /* Sign Flag: set iff most significant bit is set. */
    if (mask & EFLAGS_SF)
    {
        if (IS_NEGATIVE(res))
            set_flags(EFLAGS_SF);
        else
            clear_flags(EFLAGS_SF);
    }
    
    /* Overflow Flag: set iff sign of operands are the same but
                      sign of the result is the inverse. */
    if (mask & EFLAGS_OF)
    {
        if ( (IS_NEGATIVE(op1) && IS_NEGATIVE(op2) && !IS_NEGATIVE(res)) ||
             (!IS_NEGATIVE(op1) && !IS_NEGATIVE(op2) && IS_NEGATIVE(res)) )
            set_flags(EFLAGS_OF);
        else
            clear_flags(EFLAGS_OF);
    }
}

/**
 * \brief   Checks if the given pointer points to the emulated stack
 * \param   ptr     [in] the pointer to check
 * \return  1 if in the emulated stack, 0 if not
 */
inline int in_stack(const void* ptr)
{
    int64_t pos = BASE_ESP - (uint32_t) ptr;
    return (pos >= 0 && pos <= EMU_ESP ? 1 : 0);
}

/**
 * Dereferences a pointer.
 * If the pointer is in the emulated stack, value is taken from stack,
 * otherwise it is dereferenced from host memory and hopefully it does not
 * crash the emulator~~
 */
#define DEREF(ptr) (in_stack(ptr) ? stack[BASE_ESP - (uint32_t) (ptr)] : *(ptr))

/**
 * \brief  Pops 32-bit value from the top of the stack and unwinds the stack
 * \param  pReg     [in]  pointer to memory location to store the popped value
 */
inline void pop(uint32_t* pReg)
{
    *pReg = 0;
    
    size_t i = 0;
    for (i = 0; i < 4; ++i)
        *pReg |= stack[EMU_ESP - i] << (i * 8);
        
    gpr[ESP] += 4;
}

/**
 * \brief  Pushes 32-bit value from the top of the stack and winds the stack
 * \param  pReg     [in]  pointer to memory location of the value to be pushed
 */
inline void push(const uint32_t* pReg)
{
    size_t i = 0;
    for (i = 0; i < 4; ++i)
        stack[EMU_ESP + i + 1] = *pReg >> ((3 - i) * 8);
        
    gpr[ESP] -= 4;
}

/**
 * \brief   Increments a 32-bit register
 * \param   pReg    [in] pointer to the register to be incremented
 */
inline void inc(uint32_t* pReg)
{
	uint32_t prev_val = *pReg;
	++(*pReg);
	modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,
		*pReg, prev_val, 1);
}

/**
 * \brief   Decrements a 32-bit register
 * \param   pReg    [in] pointer to the register to be decremented
 */
inline void dec(uint32_t* pReg)
{
	uint32_t prev_val = *pReg;
	--(*pReg);
	modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,
		*pReg, prev_val, -1);
}

/**
 * dst <- dst + src (treated as signed)
 * EFLAGS affected: CF, OF, SF, ZF, AF, PF
 */
#define ADD(T, pDst, src)                                                      \
{	                                                                           \
    u##T result_u = (u##T) *pDst + (u##T) src;                                 \
    if (result_u < (u##T) *pDst || result_u < (u##T) src)                      \
        set_flags(EFLAGS_CF);                                                  \
    else                                                                       \
        clear_flags(EFLAGS_CF);                                                \
                                                                               \
    T prev_dst = *pDst;                                                        \
    *pDst += src;                                                              \
    modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,    \
	    *pDst, prev_dst, src);                                                 \
}

/**
 * dst <- dst _bitwise_and_ src
 * EFLAGS affected: PF, ZF, SF; cleared: OF, CF
 */
#define AND(T, pDst, src)                                                      \
{                                                                              \
    *pDst &= src;                                                              \
	modify_flags(EFLAGS_PF | EFLAGS_ZF | EFLAGS_SF, *pDst, 0, 0);              \
	clear_flags(EFLAGS_OF | EFLAGS_CF);                                        \
}

/**
 * dst <- dst - src
 * EFLAGS affected: CF, OF, SF, ZF, AF, PF
 */
#define SUB(T, pDst, src)                                                      \
{                                                                              \
    if ((u##T) *pDst < (u##T) src)                                             \
	    set_flags(EFLAGS_CF);                                                  \
    else                                                                       \
	    clear_flags(EFLAGS_CF);                                                \
                                                                               \
    T prev_dst = *pDst;                                                        \
    *pDst -= src;                                                              \
                                                                               \
    modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,    \
	    *pDst, prev_dst, -1 * src);                                            \
}

/**
 * dst <- dst _bitwise_xor_ src
 * EFLAGS affected: PF, ZF, SF; cleared: OF, CF
 */
#define XOR(T, pDst, src)                                                      \
{                                                                              \
    *pDst ^= src;                                                              \
	modify_flags(EFLAGS_PF | EFLAGS_ZF | EFLAGS_SF, *pDst, 0, 0);              \
	clear_flags(EFLAGS_OF | EFLAGS_CF);                                        \
}

/**
 * tmp <- dst - src
 * EFLAGS affected: CF, OF, SF, ZF, AF, PF
 */
#define CMP(T, dst, src)                                                       \
{                                                                              \
	if ((u##T) dst < (u##T) src)                                               \
		set_flags(EFLAGS_CF);                                                  \
	else                                                                       \
		clear_flags(EFLAGS_CF);                                                \
	                                                                           \
	T _cmp_signed = (T) dst - (T) src;                                         \
	modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,    \
		_cmp_signed, dst, -1 * src);                                           \
}

/**
 * dst <- src
 * EFLAGS affected: none
 */
#define MOV(T, pDst, src)                                                      \
{                                                                              \
    *pDst = src;                                                               \
}

/**
 * tmp <- dst _bitwise_and_ src
 * EFLAGS affected: SF, ZF, PF, CF, OF
 */
#define TEST(T, dst, src)                                                      \
{                                                                              \
    u##T _temp = src & dst;                                                    \
    modify_flags(EFLAGS_SF | EFLAGS_ZF | EFLAGS_PF, _temp, dst, src);          \
    clear_flags(EFLAGS_CF | EFLAGS_OF);                                        \
}

/**
 * dst <- dst _shift_arithmetic_right_  src
 * EFLAGS affected: CF, OF
 */
#define SAR(T, pDst, src)                                                      \
{                                                                              \
	if (*pDst & (1 >> src))                                                    \
		set_flags(EFLAGS_CF);                                                  \
	else                                                                       \
		clear_flags(EFLAGS_CF);                                                \
		                                                                       \
	if (src == 1)                                                              \
		clear_flags(EFLAGS_OF);                                                \
	                                                                           \
	*pDst = *pDst >> src;                                                      \
}

/* Macros for addressing modes */

/* Gb: byte-sized register */
#define PTR_Gb  (gprbyte[ctx.eff_reg])
#define VAL_Gb  DEREF(PTR_Gb)

/* Eb: byte-sized effective address (register or memory) */
#define PTR_Eb  ((int8_t*) ctx.ea)
#define VAL_Eb  DEREF(PTR_Eb)

/* Gv: dword-sized register */
#define PTR_Gv  (&(gpr[ctx.eff_reg]))
#define VAL_Gv  DEREF(PTR_Gv)

/* Ev: dword-sized effective address (register or memory) */
#define PTR_Ev  ((int32_t*) ctx.ea)
#define VAL_Ev  DEREF(PTR_Ev)

/* Ib: byte-sized immediate value */
#define VAL_Ib  (ctx.immed)

/* Iz: dword-sized immediate value */
#define VAL_Iz  (ctx.immed_l)

/* AL: the AL register (LSB of EAX) */
#define PTR_AL  (gprbyte[AL])
#define VAL_AL  DEREF(PTR_AL)

/**
 * \brief   Emulates n bytes of the code
 * \param   pCode      [in]  pointer to the code
 * \param   nCodeLen   [in]  number of bytes to emulate
 */
void emulate(unsigned char* pCode, size_t nCodeLen)
{   
    BEGIN_OPCODE_MAP
    
    /* Formats:
     *
     * MAP1(OPCODE, UNIQUE_NAME, ADDRESSING_MODE_FLAGS)
     *  => Maps 1 opcode
     *
     * MAPR(OPCODE_START, OPCODE_END, UNIQUE_NAME, ADDRESSING_MODE_FLAGS)
     *  => Maps a range of opcodes (inclusive of start and end)
     *
     * MAP1_EXT(OPCODE, EXTENSION, UNIQUE_NAME, ADDRESSING_MODE_FLAGS)
     *  => Maps 1 opcode with extension
     */
    
    MAP1(0x00,          add_Eb_Gb,  MODRM)
    MAP1(0x01,          add_Ev_Gv,  MODRM)
    MAP1(0x02,          add_Gb_Eb,  MODRM)
    MAP1(0x03,          add_Gv_Ev,  MODRM)
    MAP1(0x04,          add_AL_Ib,  SRC_IMM_BYTE)
    
    MAP1(0x20,          and_Eb_Gb,  MODRM)
    MAP1(0x21,          and_Ev_Gv,  MODRM)
    MAP1(0x22,          and_Gb_Eb,  MODRM)
    MAP1(0x23,          and_Gv_Ev,  MODRM)
    MAP1(0x24,          and_AL_Ib,  SRC_IMM_BYTE)
    
    MAP1(0x28,          sub_Eb_Gb,  MODRM)
    MAP1(0x29,          sub_Ev_Gv,  MODRM)
    MAP1(0x2a,          sub_Gb_Eb,  MODRM)
    MAP1(0x2b,          sub_Gv_Ev,  MODRM)
    MAP1(0x2c,          sub_AL_Ib,  SRC_IMM_BYTE)
    
    MAP1(0x30,          xor_Eb_Gb,  MODRM)
    MAP1(0x31,          xor_Ev_Gv,  MODRM)
    MAP1(0x32,          xor_Gb_Eb,  MODRM)
    MAP1(0x33,          xor_Gv_Ev,  MODRM)
    MAP1(0x34,          xor_AL_Ib,  SRC_IMM_BYTE)
    
    MAP1(0x38,          cmp_Eb_Gb,  MODRM)
    MAP1(0x39,          cmp_Ev_Gv,  MODRM)
    MAP1(0x3a,          cmp_Gb_Eb,  MODRM)
    MAP1(0x3b,          cmp_Gv_Ev,  MODRM)
    MAP1(0x3c,          cmp_AL_Ib,  SRC_IMM_BYTE)
    
    MAPR(0x40, 0x47,    inc_gpr,    REG_ALT_ENC)
    MAPR(0x48, 0x4f,    dec_gpr,    REG_ALT_ENC)
    
    MAPR(0x50, 0x57,    push_gpr,   REG_ALT_ENC)
    MAPR(0x58, 0x5f,    pop_gpr,    REG_ALT_ENC)
    
    MAP1_EXT(0x80, 0x0, add_Eb_Ib,  SRC_IMM_BYTE | MODRM)
    MAP1_EXT(0x80, 0x4, and_Eb_Ib,  SRC_IMM_BYTE | MODRM)
    MAP1_EXT(0x80, 0x5, sub_Eb_Ib,  SRC_IMM_BYTE | MODRM)
    MAP1_EXT(0x80, 0x6, xor_Eb_Ib,  SRC_IMM_BYTE | MODRM)
    MAP1_EXT(0x80, 0x7, cmp_Eb_Ib,  SRC_IMM_BYTE | MODRM)
    
    MAP1_EXT(0x81, 0x0, add_Ev_Iz,  SRC_IMM_LONG | EXTENSION | MODRM)
    MAP1_EXT(0x81, 0x4, and_Ev_Iz,  SRC_IMM_LONG | EXTENSION | MODRM)
    MAP1_EXT(0x81, 0x5, sub_Ev_Iz,  SRC_IMM_LONG | EXTENSION | MODRM)
    MAP1_EXT(0x81, 0x6, xor_Ev_Iz,  SRC_IMM_LONG | EXTENSION | MODRM)
    MAP1_EXT(0x81, 0x7, cmp_Ev_Iz,  SRC_IMM_LONG | EXTENSION | MODRM)
    
    MAP1_EXT(0x83, 0x0, add_Ev_Ib,  SRC_IMM_BYTE | EXTENSION | MODRM)
    MAP1_EXT(0x83, 0x4, and_Ev_Ib,  SRC_IMM_BYTE | EXTENSION | MODRM)
    MAP1_EXT(0x83, 0x5, sub_Ev_Ib,  SRC_IMM_BYTE | EXTENSION | MODRM)
    MAP1_EXT(0x83, 0x6, xor_Ev_Ib,  SRC_IMM_BYTE | EXTENSION | MODRM)
    MAP1_EXT(0x83, 0x7, cmp_Ev_Ib,  SRC_IMM_BYTE | EXTENSION | MODRM)
    
    MAP1(0x84,          test_Eb_Gb, MODRM)
    MAP1(0x85,          test_Ev_Gv, MODRM)
    
    MAP1(0x89,          mov_Ev_Gv,  MODRM)
    MAP1(0x8b,          mov_Gv_Ev,  MODRM)
    
    MAP1(0x8d,          lea_Gv_m,   MODRM)
    
    MAP1(0x90,          nop,        0)
    
    MAP1_EXT(0xc0, 0x7, sar_Eb_Ib,  SRC_IMM_BYTE | EXTENSION | MODRM)
    MAP1_EXT(0xc1, 0x7, sar_Ev_Ib,  SRC_IMM_BYTE | EXTENSION | MODRM)
    
    MAP1(0xc6,          mov_Eb_Ib,  SRC_IMM_BYTE | MODRM)
    MAP1(0xc7,          mov_Ev_Iz,  SRC_IMM_LONG | MODRM)
    
    END_OPCODE_MAP
    
    BEGIN_DISPATCH
    
    /* Format: INSTR(UNIQUE_NAME) { __any_code__ }
     * UNIQUE_NAME must match the opcode map
     */
    
    INSTR(add_Eb_Gb)  { ADD(int8_t,  PTR_Eb,  VAL_Gb); }
    INSTR(add_Ev_Gv)  { ADD(int32_t, PTR_Ev,  VAL_Gv); }
    INSTR(add_Gb_Eb)  { ADD(int8_t,  PTR_Gb,  VAL_Eb); }
    INSTR(add_Gv_Ev)  { ADD(int32_t, PTR_Gv,  VAL_Ev); }
    INSTR(add_AL_Ib)  { ADD(int8_t,  PTR_AL,  VAL_Ib); }
    
    INSTR(and_Eb_Gb)  { AND(int8_t,  PTR_Eb,  VAL_Gb); }
    INSTR(and_Ev_Gv)  { AND(int32_t, PTR_Ev,  VAL_Gv); }
    INSTR(and_Gb_Eb)  { AND(int8_t,  PTR_Gb,  VAL_Eb); }
    INSTR(and_Gv_Ev)  { AND(int32_t, PTR_Gv,  VAL_Ev); }
    INSTR(and_AL_Ib)  { AND(int8_t,  PTR_AL,  VAL_Ib); }
    
    INSTR(sub_Eb_Gb)  { SUB(int8_t,  PTR_Eb,  VAL_Gb); }
    INSTR(sub_Ev_Gv)  { SUB(int32_t, PTR_Ev,  VAL_Gv); }
    INSTR(sub_Gb_Eb)  { SUB(int8_t,  PTR_Gb,  VAL_Eb); }
    INSTR(sub_Gv_Ev)  { SUB(int32_t, PTR_Gv,  VAL_Ev); }
    INSTR(sub_AL_Ib)  { SUB(int8_t,  PTR_AL,  VAL_Ib); }
    
    INSTR(xor_Eb_Gb)  { XOR(int8_t,  PTR_Eb,  VAL_Gb); }
    INSTR(xor_Ev_Gv)  { XOR(int32_t, PTR_Ev,  VAL_Gv); }
    INSTR(xor_Gb_Eb)  { XOR(int8_t,  PTR_Gb,  VAL_Eb); }
    INSTR(xor_Gv_Ev)  { XOR(int32_t, PTR_Gv,  VAL_Ev); }
    INSTR(xor_AL_Ib)  { XOR(int8_t,  PTR_AL,  VAL_Ib); }
    
    INSTR(cmp_Eb_Gb)  { CMP(int8_t,  VAL_Eb,  VAL_Gb); }
    INSTR(cmp_Ev_Gv)  { CMP(int32_t, VAL_Ev,  VAL_Gv); }
    INSTR(cmp_Gb_Eb)  { CMP(int8_t,  VAL_Gb,  VAL_Eb); }
    INSTR(cmp_Gv_Ev)  { CMP(int32_t, VAL_Gv,  VAL_Ev); }
    INSTR(cmp_AL_Ib)  { CMP(int8_t,  VAL_AL,  VAL_Ib); }

	INSTR(inc_gpr)    { inc(PTR_Gv);  }
	INSTR(dec_gpr)    { dec(PTR_Gv);  }

	INSTR(push_gpr)   { push(PTR_Gv); }
	INSTR(pop_gpr)    { pop (PTR_Gv); }

    INSTR(add_Eb_Ib)  { ADD(int8_t,  PTR_Eb,  VAL_Ib); }
    INSTR(and_Eb_Ib)  { AND(int8_t,  PTR_Eb,  VAL_Ib); }
    INSTR(sub_Eb_Ib)  { SUB(int8_t,  PTR_Eb,  VAL_Ib); }
    INSTR(xor_Eb_Ib)  { XOR(int8_t,  PTR_Eb,  VAL_Ib); }
	INSTR(cmp_Eb_Ib)  { CMP(int8_t,  VAL_Eb,  VAL_Ib); }
	
	INSTR(add_Ev_Iz)  { ADD(int32_t, PTR_Ev,  VAL_Iz); }
	INSTR(and_Ev_Iz)  { AND(int32_t, PTR_Ev,  VAL_Iz); }
	INSTR(sub_Ev_Iz)  { SUB(int32_t, PTR_Ev,  VAL_Iz); }
	INSTR(xor_Ev_Iz)  { XOR(int32_t, PTR_Ev,  VAL_Iz); }
	INSTR(cmp_Ev_Iz)  { CMP(int32_t, VAL_Ev,  VAL_Iz); }

    INSTR(add_Ev_Ib)  { ADD(int32_t, PTR_Ev,  VAL_Ib); }
	INSTR(and_Ev_Ib)  { AND(int32_t, PTR_Ev,  VAL_Ib); }
	INSTR(sub_Ev_Ib)  { SUB(int32_t, PTR_Ev,  VAL_Ib); }
	INSTR(xor_Ev_Ib)  { XOR(int32_t, PTR_Ev,  VAL_Ib); }
	INSTR(cmp_Ev_Ib)  { CMP(int32_t, VAL_Ev,  VAL_Ib); }
	
	INSTR(test_Eb_Gb) { TEST(int8_t,  VAL_Eb, VAL_Gb); }
	INSTR(test_Ev_Gv) { TEST(int32_t, VAL_Ev, VAL_Gv); }

	INSTR(mov_Ev_Gv)  { MOV(int32_t, PTR_Ev,  VAL_Gv); }
	INSTR(mov_Gv_Ev)  { MOV(int32_t, PTR_Gv,  VAL_Ev); }

	INSTR(lea_Gv_m)   { *PTR_Gv = (int32_t) PTR_Ev;    }
	
    INSTR(nop)        { }

    INSTR(sar_Eb_Ib)  { SAR(int32_t, PTR_Eb,  VAL_Ib); }
	INSTR(sar_Ev_Ib)  { SAR(int32_t, PTR_Ev,  VAL_Ib); }
	
	INSTR(mov_Eb_Ib)  { MOV(int8_t,  PTR_Eb,  VAL_Ib); }
	INSTR(mov_Ev_Iz)  { MOV(int32_t, PTR_Ev,  VAL_Iz); }
		
	ON_CANNOT_EMULATE /* Opcodes that are not implemented goes here */
	{
		printf("--- EMULATION FAILED [0x%02x]\n", pCode[EMU_EIP]);
	}
		
	ON_HALT
	{
		printf("--- HALT\n");
	}
}

/* Point of entry of the application */
int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("Usage: ./x86emu [input-file]\n");
        return 1;
    }
    
    unsigned char*  pCode = NULL;
    size_t          nCodeLen = 0;
    load_code(argv[1], &pCode, &nCodeLen);
    
    if (!pCode)
    {
        printf("Failed to read input file: %s", argv[1]);
        return -1;
    }
    
    printf("Input file: %s\n", argv[1]);
    print_code(pCode, 0, nCodeLen);
    printf("\n");
    
    emulate(pCode, nCodeLen);
	
	if (pCode)
	{
		free(pCode);
		pCode = NULL;
	}
	return 0;
}

