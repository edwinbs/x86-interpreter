/**
 * registers.h
 * Declaration of the emulated x86 registers
 *
 * @author  Edwin Boaz Soenaryo
 * @email   edwinbs@comp.nus.edu.sg
 */

#pragma once

#include <stdint.h>

/* General Purpose Registers */
#define EAX         0
#define ECX         1
#define EDX         2
#define EBX         3
#define ESP         4
#define EBP         5
#define ESI         6
#define EDI         7

uint32_t gpr[8]   = {0};
uint8_t* gprbyte[8] = {0};

#define BASE_EIP    0x8048354
uint32_t eip;
#define EMU_EIP     (eip - BASE_EIP)

#define BASE_ESP    0xbf8db0bc
#define EMU_ESP     (BASE_ESP - gpr[ESP])

uint32_t eflags;

/* Segment registers (not implemented) */
uint32_t cs;
uint32_t ss;
uint32_t ds;
uint32_t es;
uint32_t fs;
uint32_t gs;

/* Index of 8-bit registers */
#define AL              0
#define CL              1
#define DL              2
#define BL              3
#define AH              4
#define CH              5
#define DH              6
#define BH              7

/* These macros are used to get pointers to 8-bit registers */
#define LO_OF(reg)      ((uint8_t*) &(gpr[reg])) + 0
#define HI_OF(reg)      ((uint8_t*) &(gpr[reg])) + 1

/* Some EFLAGS masks */
#define EFLAGS_CF       (1<<0)
#define EFLAGS_PF       (1<<2)
#define EFLAGS_AF       (1<<4)
#define EFLAGS_ZF       (1<<6)
#define EFLAGS_SF       (1<<7)
#define EFLAGS_TF       (1<<8)
#define EFLAGS_IF       (1<<9)
#define EFLAGS_DF       (1<<10)
#define EFLAGS_OF       (1<<11)
