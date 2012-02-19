#pragma once

#include <stdint.h>

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
uint32_t eip;
#define EIP         (eip - BASE_EIP)

uint32_t eflags;

uint32_t cs;
uint32_t ss;
uint32_t ds;
uint32_t es;
uint32_t fs;
uint32_t gs;