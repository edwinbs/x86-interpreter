/**
 * x86emu.c
 * A partial x86 emulator for CS6270
 *
 * @author  Edwin Boaz Soenaryo
 * @email   edwinbs@comp.nus.edu.sg
 */

#include <stdarg.h>
#include "registers.h"

#include <stdlib.h>
#include <stdio.h>


#define MAX_CODE_LEN 1024

/* Flags to indicate addressing modes */
#define SRC_IMM_BYTE    (1<<0)  /* Immediate 8-bit operand */
#define DST_REG         (1<<1)
#define EXTENSION       (1<<2)

/* Addressing mode description for instructions with one-byte opcode */
uint32_t am[256] = { 0 };

/* 1KB of stack */
uint8_t stack[1024] = { 0 };

typedef struct
{
    uint8_t     opcode;
    int32_t*    pDst;
    int32_t     ea;
    uint8_t     modregrm;
    uint8_t     mod;
    uint8_t     reg;
    uint8_t     rm;
    int8_t      immed;
} context_s;

#define PRINTREG(name, val) printf("%s\t0x%x\n", name, val)
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

inline void print_stack()
{
    printf("STACK\n");
    uint32_t i = 0;
    for (i = 0; i <= EMU_ESP; ++i)
        printf("0x%08x:\t0x%02x %s\n", (BASE_ESP-i), stack[i], (i==EMU_ESP?"<- esp":""));
    printf("\n");
}

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

void print_code(unsigned char* pCode, size_t nOffset, size_t nCount)
{
    int i = 0;
    for (i = 0; i < nCount; ++i)
        printf("%02x ", pCode[nOffset + i]);
}

void init_amode()
{
    am[0x34] = 0;                                   /* xor  AL, Ib */
    am[0x45] = DST_REG;                             /* inc  %ebp   */
    am[0x50] = 0;                                   /* push %eax   */
    am[0x5d] = DST_REG;                             /* pop  %ebp   */
    am[0x80] = DST_REG | SRC_IMM_BYTE;              /* Immed Grp 1 */
    am[0x83] = SRC_IMM_BYTE | DST_REG | EXTENSION;
    am[0x89] = 0;                                   /* mov  Ev, Gv */
    am[0x8d] = DST_REG;                             /* lea  Gv, M  */
    am[0xc1] = SRC_IMM_BYTE | DST_REG | EXTENSION;  /* sar  Eb, Ib */
}

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

//Returns the number of bytes consumed
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

#define AM(flag) (am[pCtx->opcode] & flag)

inline void decode_instr(unsigned char* pCode, context_s* pCtx)
{
    size_t pos = 0;
    
    pCtx->opcode = *pCode;
    ++pos;
    
    pos += decode_regrm(pCode + pos, pCtx);
    
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
}

inline void set_flags(uint32_t mask)
{
    eflags |= mask;
}

inline void clear_flags(uint32_t mask)
{
    eflags &= (~mask);
}

#define IS_NEGATIVE(x) ((x) & 0x80000000)

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
    
    /* Overflow Flag */
    if (mask & EFLAGS_OF)
    {
        if ( (IS_NEGATIVE(op1) && IS_NEGATIVE(op2) && !IS_NEGATIVE(result)) ||
             (!IS_NEGATIVE(op1) && !IS_NEGATIVE(op2) && IS_NEGATIVE(result)) )
            set_flags(EFLAGS_OF);
        else
            clear_flags(EFLAGS_OF);
    }
}

inline void pop(uint32_t* pReg)
{
    *pReg = 0;
    
    size_t i = 0;
    for (i = 0; i < 4; ++i)
        *pReg |= stack[EMU_ESP - i] << (i * 8);
        
    gpr[ESP] += 4;
}

inline void push(const uint32_t* pReg)
{
    size_t i = 0;
    for (i = 0; i < 4; ++i)
        stack[EMU_ESP + i + 1] = *pReg >> ((3 - i) * 8);
        
    gpr[ESP] -= 4;
}

void start_emulator(unsigned char* pCode, size_t nCodeLen)
{   
    init_amode();
    init_registers();
    
    print_all_registers();
    getchar();
    
    context_s   ctx;
    int8_t      tmp_b;
    int32_t     tmp_l;
    
    size_t      prev_instr_offset = 0;
    char*       last_instr_name = "";
    
    while (EMU_EIP < nCodeLen)
    {
        decode_instr(pCode + EMU_EIP, &ctx);
        switch (ctx.opcode)
        {
        case 0x34: /* xor AL, Ib */
            last_instr_name = "xor";
            gpr[EAX] ^= (ctx.modregrm & REG_L);
            
            modify_flags(EFLAGS_PF | EFLAGS_ZF | EFLAGS_SF, gpr[EAX] & REG_L, 0, 0); //operands not required
            clear_flags(EFLAGS_OF | EFLAGS_CF);
            
            eip += 2;
            break;

        case 0x40 ... 0x47: /* inc gpr */
            last_instr_name = "inc";
            tmp_l = gpr[ctx.opcode - 0x40];
            ++(gpr[ctx.opcode - 0x40]);
            modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,
                gpr[ctx.opcode - 0x40], tmp_l, 1);
            eip += 1;
            break;
            
        case 0x48 ... 0x4f: /* dec gpr */
            last_instr_name = "dec";
            tmp_l = gpr[ctx.opcode - 0x48];
            --(gpr[ctx.opcode - 0x48]);
            modify_flags(EFLAGS_OF | EFLAGS_SF | EFLAGS_ZF | EFLAGS_AF | EFLAGS_PF,
                gpr[ctx.opcode - 0x40], tmp_l, -1);
            eip += 1;
            break;

        case 0x50 ... 0x57: /* push gpr */
            last_instr_name = "push";
            push(&gpr[ctx.opcode - 0x50]);
            eip += 1;
            break;

        case 0x58 ... 0x5f: /* pop gpr */
            last_instr_name = "pop";
            pop(&gpr[ctx.opcode - 0x58]);
            eip += 1;
            break;

        case 0x80: /* Immediate Grp 1 */
            switch (ctx.reg)
            {
            case 0x7:   /* cmp */
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
                
                eip += 5;
                break;
            }
                
            default:
                printf("[ext 0x%x] not implemented\n", ctx.reg);
                eip += 5;
            }
            break;

        case 0x83: /* Immediate Grp 1 */
            switch (ctx.reg)
            {
            case 0x4:
                last_instr_name = "and";
                *(ctx.pDst) &= ctx.immed;
                
                modify_flags(EFLAGS_PF | EFLAGS_ZF | EFLAGS_SF, *(ctx.pDst), 0, 0); //operands not required
                clear_flags(EFLAGS_OF | EFLAGS_CF);
                
                eip += 3;
                break;
                
            case 0x5:
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
                    
                eip += 3;
                break;
            }
                
            default:
                printf("[ext 0x%02x] not implemented\n", ctx.reg);
                eip += 3;
            }
            break;

        case 0x8d: /* lea Gv, m */
            last_instr_name = "leal";
            *(ctx.pDst) = ctx.ea;
            eip += 4;
            break;

        case 0x89: /* mov Ev, Gv */
            last_instr_name = "movl";
            switch (ctx.mod)
            {
            case 0x3: // Mod=11
                gpr[ctx.rm] = gpr[ctx.reg];
                eip += 2;
                break;
                
            default:
                printf("[mod 0x%x] not understood\n", ctx.mod);
                eip += 2;
            }
            break;

        case 0xc1: /* Shift Grp 2 */
            switch (ctx.reg)
            {
            case 0x7:
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
                eip += 3;
                break;
                
            default:
                printf("[ext 0x%02x] not implemented\n", ctx.reg);
                eip += 3;
            }
            break;
            
        default:
            printf("EMULATION FAILED [0x%02x]\n", pCode[EMU_EIP]);
            eip += 1;
        }
        
        print_code(pCode, prev_instr_offset, EMU_EIP - prev_instr_offset);
        printf("\t%s\n\n", last_instr_name);
        
        prev_instr_offset = EMU_EIP;
        
        print_all_registers();
        print_stack();
        getchar();
    }
}

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
    
    start_emulator(pCode, nCodeLen);
}
