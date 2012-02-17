/**
 * x86emu.c
 * A partial x86 emulator for CS6270
 *
 * @author  Edwin Boaz Soenaryo
 * @email   edwinbs@comp.nus.edu.sg
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>


#define PRINTREG(name, val) printf("%s\t0x%x\n", name, val)

#define MAX_CODE_LEN 1024

#define EAX         0x000
#define ECX         0x001
#define EDX         0x010
#define EBX         0x011
#define ESP         0x100
#define EBP         0x101
#define ESI         0x110
#define EDI         0x111

uint32_t gpr[8]   = {0};

#define BASE_EIP    0x8048354
uint32_t eip      = BASE_EIP;
#define EIP         (eip - BASE_EIP)

uint32_t eflags   = 0x246;

uint32_t cs	      = 0x73;
uint32_t ss	      = 0x7b;
uint32_t ds	      = 0x7b;
uint32_t es	      = 0x7b;
uint32_t fs       = 0x0;
uint32_t gs       = 0x33;

#define LEA_Gv_M    0x8D
#define AND_AL_Ib   0x24
#define PUSH_EAX    0x50
#define SAR_Eb_Ib   0xc1
#define XOR_AL_Ib   0x34
#define MOV_Ev_Gv   0x89
#define INC_EBP     0x45
#define SUB_Ev_Ib   0x83
#define CMP_Eb_Ib   0x80
#define POP_EBP     0x5d

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

void init_registers()
{
    gpr[EAX] = 0xbf8db144;
    gpr[ECX] = 0x88c5ffb;
    gpr[EDX] = 0x1;
    gpr[EBX] = 0xae5ff4;
    gpr[ESP] = 0xbf8db0bc;
    gpr[EBP] = 0xbf8db118;
    gpr[ESI] = 0x9a0ca0;
    gpr[EDI] = 0x0;
}

void start_emulator(unsigned char* pCode, size_t nCodeLen)
{
    init_registers();
    
    while (EIP < nCodeLen)
    {
        switch (pCode[EIP])
        {
        //LEA - Load Effective Address
        case LEA_Gv_M:
            printf("leal\n");
            eip += 2;
            break;
            
        //AND - Logical AND
        case AND_AL_Ib:
            printf("andl\n");
            eip += 5;
            break;
            
        //PUSH - Push Segment Register onto the Stack
        case PUSH_EAX:
            printf("pushl\t%%eax\n");
            eip += 1;
            break;
            
        //SAR - Shift Arithmetic Right
        case SAR_Eb_Ib:   
            printf("sar\n");
            eip += 3;
            break;
            
        //XOR - Logical Exclusive OR
        case XOR_AL_Ib:
            printf("xor\n");
            eip += 2;
            break;
            
        //MOV - Move Data
        case MOV_Ev_Gv:
            printf("movl\n");
            eip += 2;
            break;
           
        //INC - Increment by 1
        case INC_EBP:
            printf("inc\n");
            eip += 1;
            break;
            
        //SUB - Integer Subtraction
        case SUB_Ev_Ib:
            printf("subl\n");
            eip += 3;
            break;
        
        //CMP - Compare Two Operands
        case CMP_Eb_Ib:
            printf("cmpb\n");
            eip += 5;
            break;
            
        //POP - Pop a Word from the Stack
        case POP_EBP:
            printf("popl\t%%ebp\n");
            eip += 1;
            break;
            
        default:
            printf("(%02x) not implemented\n", pCode[EIP]);
            eip += 1;
        }
        print_all_registers();
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
    
    print_code(argv[1], pCode, nCodeLen);
    start_emulator(pCode, nCodeLen);
}
