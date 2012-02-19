/**
 * x86emu.c
 * A partial x86 emulator for CS6270
 *
 * @author  Edwin Boaz Soenaryo
 * @email   edwinbs@comp.nus.edu.sg
 */

#include "registers.h"

#include <stdlib.h>
#include <stdio.h>


#define PRINTREG(name, val) printf("%s\t0x%x\n", name, val)

#define MAX_CODE_LEN 1024

/* Flags to indicate addressing modes */
#define SRC_IMM_BYTE    (1<<0)  /* Immediate 8-bit operand */
#define SRC_STACK       (1<<1)
#define SRC_REG         (1<<2)

#define DST_REG         (1<<3)
#define DST_ACC         (1<<4)
#define DST_STACK       (1<<5)
#define DST_MEM         (1<<6)

#define MOD_RM          (1<<7)

#define MOV             (1<<8)

/* Addressing mode description for instructions with one-byte opcode */
uint32_t am[256] = { 0 };

#define AM(reg, flag) (am[reg] & flag)

typedef struct
{
    uint8_t     opcode;
    uint32_t*   pDst;
    uint32_t    ea;
    uint8_t     mod;
    uint8_t     reg;
    uint8_t     rm;
} context_s;

inline void print_all_registers()
{
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

void print_code(char* filename, unsigned char* pCode, size_t nCodeLen)
{
    printf("input: %s\n", filename);
    
    int i = 0;
    for (i = 0; i < nCodeLen; ++i)
        printf("%02x ", pCode[i]);
    printf("\n");
}

void init_amode()
{
    am[0x24] = SRC_IMM_BYTE | DST_ACC;               /* and  AL, Ib */
    am[0x34] = 0;                                    /* xor  AL, Ib */
    am[0x45] = DST_REG;                              /* inc  %ebp   */
    am[0x50] = SRC_REG | DST_STACK;                  /* push %eax   */
    am[0x5d] = SRC_STACK | DST_REG;                  /* pop  %ebp   */
    am[0x80] = 0; //TODO                             /* cmp  Eb, Ib */
    am[0x83] = 0; //TODO                             /* sub  Ev, Ib */
    am[0x89] = SRC_REG | DST_MEM | MOD_RM | MOV;     /* mov  Ev, Gv */
    am[0x8d] = DST_REG | MOD_RM;                     /* lea  Gv, M  */
    am[0xc1] = SRC_IMM_BYTE | DST_MEM | MOD_RM;      /* sar  Eb, Ib */
}

void init_registers()
{
    gpr[EAX]    = 0xbf8db144;
    gpr[ECX]    = 0x88c5ffb;
    gpr[EDX]    = 0x1;
    gpr[EBX]    = 0xae5ff4;
    gpr[ESP]    = 0xbf8db0bc;
    gpr[EBP]    = 0xbf8db118;
    gpr[ESI]    = 0x9a0ca0;
    gpr[EDI]    = 0x0;
    
    eip         = BASE_EIP;
    eflags      = 0x246;

    cs	        = 0x73;
    ss	        = 0x7b;
    ds	        = 0x7b;
    es	        = 0x7b;
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
        case 5: /* Oh WTF */ break;
        case 6: pCtx->ea = gpr[ESI]; break;
        case 7: pCtx->ea = gpr[EDI]; break;
    }
}

//Returns the number of bytes consumed
inline size_t decode_regrm(unsigned char* pModRMByte, context_s* pCtx)
{
    uint8_t bSIB = 0;
    
    printf("modrm_byte = 0x%x\n", *pModRMByte);
    
    pCtx->mod = (*pModRMByte       ) >> 6;
    pCtx->reg = (*pModRMByte & 0x38) >> 3;
    pCtx->rm  = (*pModRMByte & 0x07);
    
    printf("mod = 0x%x\n", pCtx->mod);
    printf("reg = 0x%x\n", pCtx->reg);
    printf("rm  = 0x%x\n", pCtx->rm);
    
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
    
    if (bSIB)
    {
        decode_sib(pModRMByte + 1, pCtx);
    }
    
    if (pCtx->mod == 1)
    {
        int8_t disp8 = (int8_t) *(pModRMByte + 2);
        pCtx->ea += disp8;
    }
}

inline void decode_instr(unsigned char* pCode, context_s* pCtx)
{
    pCtx->opcode = *pCode;
    
    decode_regrm(pCode + 1, pCtx);
    
    if (AM(pCtx->opcode, DST_REG))
    {
        printf("reg = 0x%x\n", pCtx->reg);
        pCtx->pDst = &(gpr[pCtx->reg]);
    }
}

void start_emulator(unsigned char* pCode, size_t nCodeLen)
{
    init_amode();
    init_registers();
    
    context_s ctx;
    while (EIP < nCodeLen)
    {
        print_all_registers();
        getchar();
        decode_instr(pCode + EIP, &ctx);
        switch (ctx.opcode)
        {
        case 0x34: /* xor AL, Ib */
            printf("xor\n");
            eip += 2;
            break;

        case 0x45: /* inc %ebp */
            printf("inc\n");
            eip += 1;
            break;

        case 0x50: /* push %eax */
            printf("pushl\t%%eax\n");
            eip += 1;
            break;

        case 0x5d: /* pop %ebp */
            printf("popl\t%%ebp\n");
            eip += 1;
            break;

        case 0x80: /* cmp Eb, Ib */
            printf("cmpb\n");
            eip += 5;
            break;

        case 0x83: /* sub Ev, Ib */
            printf("subl\n");
            eip += 3;
            break;

        case 0x8d: /* lea Gv, m */
            printf("leal\n");
            *(ctx.pDst) = ctx.ea;
            eip += 4;
            break;

        case 0x89: /* mov Ev, Gv */
            printf("movl\n");
            eip += 2;
            break;

        case 0xc1: /* sar Eb, Ib */
            printf("sar\n");
            eip += 3;
            break;
            
        default:
            printf("(%02x) not implemented\n", pCode[EIP]);
            eip += 1;
        }
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
    
    print_code(argv[1], pCode, nCodeLen);
    start_emulator(pCode, nCodeLen);
}
