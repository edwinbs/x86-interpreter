/**
 * x86emu.c
 * A partial x86 emulator for CS6270
 *
 * The design of this emulator can only handle 1-byte opcodes.
 * It only emulates the stack and not the heap.
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
#define DST_REG         (1<<1)	/* The destination operand is a GPR */
#define EXTENSION       (1<<2)	/* REG in MOD_REG_RM refers to opcode extension */
#define MODRM           (1<<3)	/* There is a MOD_REG_RM byte following opcode */

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
    int32_t*    pDst;		/* pointer to 32-bit destination */
    int32_t     ea;			/* effective address from MOD_REG_RM byte */
    uint8_t     modregrm;	/* the MOD_REG_RM byte */
    uint8_t     mod;		/* MOD part of the MOD_REG_RM byte */
    uint8_t     reg;		/* REG part of the MOD_REG_RM byte */
    uint8_t     rm;			/* RM part of the MOD_REG_RM byte */
    int8_t      immed;		/* 1-byte immediate operand */
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
        printf("0x%08x:\t0x%02x %s\n", (BASE_ESP-i), stack[i], (i==EMU_ESP?"<- esp":""));
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
        case 5: /* TODO */ break;
        case 6: pCtx->ea = gpr[ESI]; break;
        case 7: pCtx->ea = gpr[EDI]; break;
    }
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
    
    pCtx->modregrm = *pModRMByte;
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
            case 5: pCtx->ea = gpr[EBP]; break;
            case 6: pCtx->ea = gpr[ESI]; break;
            case 7: pCtx->ea = gpr[EDI]; break;
        }
    }
    
    ++pos;
    
    if (bSIB)
    {
        decode_sib(pModRMByte + 1, pCtx);
        ++pos;
    }
    
    if (pCtx->mod == 1)
    {
        int8_t disp8 = (int8_t) *(pModRMByte + 2);
        pCtx->ea += disp8;
        ++pos;
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
    }
    
    if (AM(SRC_IMM_BYTE))
    {
        pCtx->immed = (int8_t) *(pCode + pos);
        ++pos;
    }
    
    if (AM(DST_REG))
    {
        if (AM(EXTENSION))
            pCtx->pDst = &(gpr[pCtx->rm]);
        else
            pCtx->pDst = &(gpr[pCtx->reg]);
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
 * \brief   Modifies the required flags based on the result of previous operation.
 *          For OF, the operation is assumed to be ADD,
 *              if it is SUB then the given operand must be negated.
 *          Operands are only required if OF is chosen. Otherwise, may set to 0.
 * \param   mask    [in]  bits representing the flags to be modified
 * \param   result  [in]  result of the last operation
 * \param   op1     [in]  first operand of the last operation
 * \param   op2     [in]  second operand of the last operation
 */
inline void modify_flags(uint32_t mask, int32_t result, int32_t op1, int32_t op2)
{
    /* Parity Flag: Set iff the no of set bits in the least significant byte is even. */
    if (mask & EFLAGS_PF)
    {
        if (__builtin_popcount(result & 0x000000ff) % 2)
            clear_flags(EFLAGS_PF);
        else
            set_flags(EFLAGS_PF);
    }
        
    /* Zero Flag: set iff zero. */
    if (mask & EFLAGS_ZF)
    {
        if (result)
            clear_flags(EFLAGS_ZF);
        else
            set_flags(EFLAGS_ZF);
    }
        
    /* Sign Flag: set iff most significant bit is set. */
    if (mask & EFLAGS_SF)
    {
        if (IS_NEGATIVE(result))
            set_flags(EFLAGS_SF);
        else
            clear_flags(EFLAGS_SF);
    }
    
    /* Overflow Flag: set iff sign of operands are the same but
                      sign of the result is the inverse. */
    if (mask & EFLAGS_OF)
    {
        if ( (IS_NEGATIVE(op1) && IS_NEGATIVE(op2) && !IS_NEGATIVE(result)) ||
             (!IS_NEGATIVE(op1) && !IS_NEGATIVE(op2) && IS_NEGATIVE(result)) )
            set_flags(EFLAGS_OF);
        else
            clear_flags(EFLAGS_OF);
    }
}

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
 * \param  pReg     [in]  pointer to memory location to get the value to be pushed
 */
inline void push(const uint32_t* pReg)
{
    size_t i = 0;
    for (i = 0; i < 4; ++i)
        stack[EMU_ESP + i + 1] = *pReg >> ((3 - i) * 8);
        
    gpr[ESP] -= 4;
}

/**
 * \brief   Emulates n bytes of the code
 * \param   pCode      [in]  pointer to the code
 * \param   nCodeLen   [in]  number of bytes to emulate
 */
void emulate(unsigned char* pCode, size_t nCodeLen)
{   
    context_s   ctx;
    int8_t      tmp_b;
    int32_t     tmp_l;
    
    size_t      prev_instr_offset = 0;
    char*       last_instr_name = "";
    
    init_registers();
    
    BEGIN_OPCODE_MAP
    MAP1(0x34,          xor_AL_Ib,  MODRM)
    MAPR(0x40, 0x47,    inc_gpr,    DST_REG)
    MAPR(0x48, 0x4f,    dec_gpr,    0)
    MAPR(0x50, 0x57,    push_gpr,   0)
    MAPR(0x58, 0x5f,    pop_gpr,    DST_REG)
    MAP1_EXT(0x80, 0x7, cmp_Eb_Ib,  DST_REG | SRC_IMM_BYTE | MODRM)
    MAP1_EXT(0x83, 0x4, and_Ev_Ib,  SRC_IMM_BYTE | DST_REG | EXTENSION | MODRM)
    MAP1_EXT(0x83, 0x5, sub_Ev_Ib,  SRC_IMM_BYTE | DST_REG | EXTENSION | MODRM)
    MAP1(0x89,          mov_Ev_Gv,  MODRM)
    MAP1(0x8d,          lea_Gv_m,   DST_REG | MODRM)
    MAP1_EXT(0xc1, 0x7, sar_Ev_Ib,  SRC_IMM_BYTE | DST_REG | EXTENSION | MODRM)
    END_OPCODE_MAP
    
	INSTR(xor_AL_Ib)
	{
		last_instr_name = "xor";
		gpr[EAX] ^= (ctx.modregrm & REG_L);
		
		modify_flags(EFLAGS_PF | EFLAGS_ZF | EFLAGS_SF, gpr[EAX] & REG_L, 0, 0); //operands not required
		clear_flags(EFLAGS_OF | EFLAGS_CF);
	};

	INSTR(inc_gpr)
	{
		last_instr_name = "inc";
		tmp_l = gpr[ctx.opcode - 0x40];
		++(gpr[ctx.opcode - 0x40]);
		modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,
			gpr[ctx.opcode - 0x40], tmp_l, 1);
	};
		
	INSTR(dec_gpr)
	{
		last_instr_name = "dec";
		tmp_l = gpr[ctx.opcode - 0x48];
		--(gpr[ctx.opcode - 0x48]);
		modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,
			gpr[ctx.opcode - 0x40], tmp_l, -1);
	};

	INSTR(push_gpr)
	{
		last_instr_name = "push";
		push(&gpr[ctx.opcode - 0x50]);
	};

	INSTR(pop_gpr)
	{
		last_instr_name = "pop";
		pop(&gpr[ctx.opcode - 0x58]);
	};

	INSTR(cmp_Eb_Ib)
	{
		last_instr_name = "cmp";
		
		/* CMP works by performing subtraction as in SUB,
		   and sets flags the same way */
		int8_t src_op = stack[BASE_ESP - ctx.ea];
		
		if ((uint8_t) src_op < (uint8_t) ctx.immed)
			set_flags(EFLAGS_CF);
		else
			clear_flags(EFLAGS_CF);
		   
		tmp_b = (int8_t) src_op - (int8_t) ctx.immed;
		modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,
			tmp_b, src_op, -1 * ctx.immed);
	};

	INSTR(and_Ev_Ib)
	{
		last_instr_name = "and";
		*(ctx.pDst) &= ctx.immed;
		
		modify_flags(EFLAGS_PF | EFLAGS_ZF | EFLAGS_SF, *(ctx.pDst), 0, 0); //operands not required
		clear_flags(EFLAGS_OF | EFLAGS_CF);
	};
			
	INSTR(sub_Ev_Ib)
	{
		last_instr_name = "sub";
		/* SUB evaluates the operands as both signed and unsigned,
		   set CF according to unsigned, the rest according to signed. */
		
		if ((uint32_t) *(ctx.pDst) < (uint32_t) ctx.immed)
			set_flags(EFLAGS_CF);
		else
			clear_flags(EFLAGS_CF);
		
		/* now treat operands as signed */
		tmp_l = *(ctx.pDst);
		*(ctx.pDst) -= ctx.immed;
		
		modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,
			*(ctx.pDst), tmp_l, -1 * ctx.immed);
	};

	INSTR(mov_Ev_Gv)
	{
		last_instr_name = "movl";
		if (ctx.mod == 0x3)
			gpr[ctx.rm] = gpr[ctx.reg];
	};

	INSTR(lea_Gv_m)
	{
		last_instr_name = "leal";
		*(ctx.pDst) = ctx.ea;
	};

	INSTR(sar_Ev_Ib)
	{
		last_instr_name = "sar";
		
		/* On SAR, CF contains the last bit shifted out */
		if ((int32_t) *(ctx.pDst) & (1 >> ctx.immed))
			set_flags(EFLAGS_CF);
		else
			clear_flags(EFLAGS_CF);
			
		/* OF is only affected for 1-bit shifts */
		if (ctx.immed == 1)
		{
			/* For SAR, OF is cleared for 1-bit shifts */
			clear_flags(EFLAGS_OF);
		}
		
		*(ctx.pDst) = (int32_t) *(ctx.pDst) >> ctx.immed;
	};
		
	ON_CANNOT_EMULATE
	{
		printf("EMULATION FAILED [0x%02x]\n", pCode[EMU_EIP]);
	};
		
	ON_HALT
	{
		printf("--- The emulator is going to halt.\n");
	};
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

