#pragma once

#include <stdint.h>

#define EAX         0
#define ECX         1
#define EDX         2
#define EBX         3
#define ESP         4
#define EBP         5
#define ESI         6
#define EDI         7

uint32_t gpr[8]   = {0};

#define BASE_EIP    0x8048354
uint32_t eip;
#define EMU_EIP     (eip - BASE_EIP)

#define BASE_ESP    0xbf8db0bc
#define EMU_ESP     (BASE_ESP - gpr[ESP])

uint32_t eflags;

uint32_t cs;
uint32_t ss;
uint32_t ds;
uint32_t es;
uint32_t fs;
uint32_t gs;