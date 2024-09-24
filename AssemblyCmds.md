## iret
- Enables interrupts
- Restores the flags register
- Pops FLAGS after popping CS:IP off the stack
- When there is a privilege reduction (a numerical increate in CPL), the iret instruction will also pull an ss,sp pair off the stack.
- Updates IP from value in the stack and resume execution at IP
