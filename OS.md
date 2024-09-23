# Interrupt handlers

https://student.cs.uwaterloo.ca/~cs350/F23/notes/syscall.pdf
https://www.scs.stanford.edu/05au-cs240c/lab/i386/s15_03.htm

There are two types of interrupts.

The first type are interrupts for signalling hardware events, like that the hardware timer has elapsed or that the hard drive controller has finished transferring data to memory.

The second type are interrupts for signalling some unexpected condition. Some examples are: access to invalid memory, division by zero (actually it's "divide overflow" that occurs not only when you divide by zero, but even when you divide a very large value by a very small value), breakpoint instruction, hardware breakpoint etc. This type of exceptions are raised by CPU when it cannot complete the current instruction and usually result in terminating the current process or breaking into debugger. They are actually unrelated to CPU flags, which hold the results of the latest instruction.

The interrupt handler is a fixed entry point in the kernel.

https://student.cs.uwaterloo.ca/~cs350/F23/notes/syscall.pdf


## Special interrupt vector

### trap_table

###  TRAP_NOEC and TRAP_EC macro

## Non-maskable interrupts (NMI)

## Page faults

## Exception vs interrupt

## Interrupt vector

## Interrupt descriptor table
Defines the entry point for interrupt vector

### (IDTR) Interrupt descriptor table register
#### Trap_Init

###  IDT descriptor entry


## Interrupt gate descriptor

## trap_common
Pushes the CPU registers
## trap_entry
C handler that dispatches interrupts

## errno
where error codes are stored in POSIX


# Execution context

The environment where functions execute including their arguments, local
variables, memory.

Context is a unique set of CPU registers and a stack pointer

Context is a unique set of CPU registers and a stack pointer

Multiple execution contexts:
I Application Context: Application threads
I Kernel Context: Kernel threads, software interrupts, etc
I Interrupt Context: Interrupt handler
• Kernel and Interrupts usually the same context
• Context transitions:
I Context switch: a transitions between contexts
I Thread Switch: a transition between threads (usually between kernel contexts)

## Context switch: User to Kernel
int $60 instruction triggers the exception handler (vector 60)

### trapframe
- Saves the application context

#### trap_common 
- saves trapframe on the kernel stack
- returns to the instruction following int $60
- restores the application context
- Restores all CPU state from the trapframe

### trap_entry()
Calls trap_entry() to decode trap and Syscall_Entry()

### Syscall_Entry()
- decodes arguments and calls
- stores return value and error in trapframe
- rax: return value/error code


# TLB

# (TSS) Task state segment
## kernel stack

# IST


# Process table


