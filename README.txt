================================================================================

x86emu
A partial x86 emulator for CS6270

--------------------------------------------------------------------------------

Edwin Boaz Soenaryo (edwinbs@comp.nus.edu.sg)

Package contents:
------------------
/registers.h                Declaration of registers
/threaded_dispatch.h        Macros for threaded interpretation
/x86emu                     Binary compiled on gcc 4.4.3-4ubuntu5
/x86emu.c                   Main implementation file
/README.txt                 This file
/testcases/input1.txt       Sample input from assignment sheet
/testcases/input2.txt       Some arbitrary instructions

Usage:
-------
./x86emu <input-file>
e.g. ./x86emu testcases/input1.txt

Building:
----------
gcc -o x86emu -O3 -m32 x86emu.c

(will not build with msvc - requires stdint.h)

================================================================================
