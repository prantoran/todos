# Interrupt handlers

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


# TLB

# (TSS) Task state segment
## kernel stack

# IST

