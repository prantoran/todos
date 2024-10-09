## iret
- Enables interrupts
- Restores the flags register
- Pops FLAGS after popping CS:IP off the stack
- When there is a privilege reduction (a numerical increate in CPL), the iret instruction will also pull an ss,sp pair off the stack.
- Updates IP from value in the stack and resume execution at IP



Calling conventions for x86 32-bit architecture
• _ _cdecl: arguments are push into the stack from right to left, and the caller is
responsible for cleaning up the pressed arguments and placing the return
value in the EAX when the call is complete. This convention is used by most
C programs on x86 platforms.
• _ _stdcall: arguments are also push into the stack from right to left, and the
called party is responsible for cleaning up the pressed arguments after the call
is made, with the return value also placed in the EAX.
• _ _thiscall: an invocation convention optimized specifically for class methods
that places the “this” pointer to the class method in the ECX register and then
push the rest of the parameters into the stack.
• _ _ _ fastcall: a call convention created to speed up calls by putting the first
argument in ECX, the second in EDX, and then push the subsequent arguments
into the stack from right to left.


Call conventions for x86 64-bit architecture
• Microsoft x64-bit (x86-64) call convention: Used on Windows, the first four
parameters are placed into the RCX, RDX, R8 and R9 registers, and then push
remaining parameters into the stack from right to left.
• SystemV x64 invocation conventions: Used on Linux and MacOS, two more
registers than Microsoft’s version, using RDI, RSI, RDX, RCX, R8, R9 registers
to pass the first six parameters, and right-to-left push into stack for the rest.
