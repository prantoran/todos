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
