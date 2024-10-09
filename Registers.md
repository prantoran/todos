Caller-saved registers are saved before calling another function
- r10, r11: Scratch registers
- rdi, rsi, rdx, rcx, r8, r9: Argument registers
- rax, rdx: Return values

Callee-saved registers are saved inside the function
- rbx, r12–r15: Saved registers

Stack registers
- rsp: Stack pointer
- rbp: Frame pointer (assuming -fno-omit-framepointer)


Instructions:
- call: Call function and save return address on stack
- ret: Return from function


In IA-32, there are 8 general purpose registers (GPR): EAX, EBX, ECX, EDX, ESI, EDI, EBP, and EIP.

There are also 16-bit segment registers (CS, DS, ES, FS, GS, and SS).

EFLAGS register contains status flags.

MMX registers


• General purpose registers EAX, EBX, ECX, EDX, ESI, EDI.
• Top-of-stack Pointer Register ESP, Bottom-of-stack Pointer Register EBP.
• Instruction counter EIP (holds the address of the next instruction to be executed).
• Segment registers CS, DS, SS, ES, FS, GS.

For the x86-64 architecture, based on these registers, the E prefix is changed to R to
mark 64 bits, and eight general-purpose registers, R8 to R15 are added.

the naming conventions for splitting R8 to R15 are R8d (low
32 bits), R8w (low 16 bits), and R8b (low 8 bits).

There is also a flag register in the CPU, in which each bit represents the value of a
corresponding flag.There are some commonly used flags:
• AF: Auxiliary Carry Flag, set to 1 when the result is rounded to the third digit.
• PF: Parity flag, set to 1 when the lowest order byte of the result an arithmetic or bit
wise operation has an even or odd number of 1s.
• SF: Sign Flag, set to 1 when the sign is 1, which means it is a negative number.
• ZF: Zero Flag, set to 1 when the result is all zero.
• OF: Overflow Flag, set to 1 if the number to be operated on is a signed number
and overflow.
• CF: Carry Flag, set to 1 when the result is carried out above the highest bit, used
to determine whether overflow of unsigned numbers.
