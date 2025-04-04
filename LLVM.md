LLVM has no notion of high-
level constructs such as classes, inheritance, or exception-
handling semantics, even when compiling source languages
with these features.

LLVM does not specify a
runtime system or particular object model: it is low-level
enough that the runtime system for a particular language
can be implemented in LLVM itself. 

LLVM does not guarantee type safety, memory safety, or
language interoperability any more than the assembly lan-
guage for a physical processor does.



The LLVM compiler framework exploits the code repre-
sentation to provide a combination of five capabilities that
we believe are important in order to support lifelong anal-
ysis and transformation for arbitrary programs. In general,
these capabilities are quite difficult to obtain simultaneously,
but the LLVM design does so inherently:
(1) Persistent program information: The compilation model
preserves the LLVM representation throughout an ap-
plication’s lifetime, allowing sophisticated optimiza-
tions to be performed at all stages, including runtime
and idle time between runs.
(2) Offline code generation: Despite the last point, it is
possible to compile programs into efficient native ma-
chine code offline, using expensive code generation
techniques not suitable for runtime code generation.
This is crucial for performance-critical programs.
(3) User-based profiling and optimization: The LLVM
framework gathers profiling information at run-time in
the field so that it is representative of actual users, and
can apply it for profile-guided transformations both at
run-time and in idle time1
.
(4) Transparent runtime model: The system does not
specify any particular object model, exception seman-
tics, or runtime environment, thus allowing any lan-
guage (or combination of languages) to be compiled
using it.
(5) Uniform, whole-program compilation: Language-indep-
endence makes it possible to optimize and compile all
code comprising an application in a uniform manner
(after linking), including language-specific runtime li-
braries and system libraries

Memory locations in LLVM are not in SSA form because
many possible locations may be modified at a single store
through a pointer,

## Instruction set
supports 31 opcodes

not and neg
are implemented in terms of xor and sub,

Opcodes are overloaded

most instructions are three-address form

### phi instruction
(non-gated)  function of SSA form.



 Non-loop transformations
in SSA form are further simplified because they do
not encounter anti- or output dependences on SSA registers.

Non-memory transformations are also greatly simplified because
(unrelated to SSA) registers cannot have aliases.

LLVM also makes the Control Flow Graph (CFG) of every
function explicit in the representation.


terminator instruction
(branches, return, unwind, or invoke


## Languageindependent
Type Information,
Cast, and GetElementPtr

language-independent type system

source-language-independent
primitive types with predefined sizes (void, bool,
signed/unsigned integers from 8 to 64 bits, and single- and
double-precision floating-point types)

four derived types: pointers, arrays, structures,
and functions.

the four derived types above capture
the type information used even by sophisticated languageindependent
analyses and optimizations.

LLVM ‘cast’ instruction 

no mixedtype
operations


getelementptr instruction
address arithmetic
perform pointer arithmetic in a way that both preserves type
information and has machine-independent semantics


# Why use Static Single Assignment (SSA)?

SSA is a way of structuring the
intermediate representation so that
every variable is assigned exactly once

SSA for makes use-def chains explicit in the IR, which simplies some optimizations.

Use-def chains (multiple assignments to the same expression) are represented with $\phi$() function.

Static single-assignment form arranges for
every value computed by a program to have
a unique assignment (aka, “definition”)

A procedure is in SSA form if every variable
has (statically) exactly one definition

SSA form simplifies several important
optimizations, including various forms of
redundancy elimination

## Chordal graphs

the interference graph for
an SSA form IR is always chordal

## Creating SSA form

To translate into SSA form:
• Insert trivial Φ functions at join points for each
live variable
• Φ(t,t,…,t), where the number of t’s is the
number of incoming flow edges
• Globally analyze and rename definitions and uses
of variables to establish SSA property
After we are done with our optimizations, we
can throw away all of the statements
involving Φ functions (ie, “unSSA”)


## Dominance frontiers

An SSA form with the minimum number of Φ
functions can be created by using dominance
frontiers

Definitions:
• In a flowgraph, node a dominates node b (“a dom b”)
if every possible execution path from entry to b
includes a
• If a and b are different nodes, we say that a strictly
dominates b (“a sdom b”)
• If a sdom b, and there is no c such that a sdom c and
c sdom b, we say that a is the immediate dominator
of b (“a idom b”)


For a node a, the dominance frontier
of a, DF[a], is the set of all nodes b
such that a strictly dominates an
immediate precedessor of b but not b
itself
More formally:
• DF[a] = {b | (∃c∈Pred(b) such that a
dom c but not a sdom b}

### Computing DF[a]

A naïve approach to computing DF[a] for all
nodes a would require quadratic time
However, an approach that usually is linear
time involves cutting into parts:
• DFl[a] = {b ∈ Succ(a) | idom(b)≠a}
• DFu[a,c] = {b ∈ DF[c] | idom(c)=a ∧ idom(b)≠a}

Then:
• DF[a] = DFl[a] ∪
∪ DF [a,c]

What we want, in the end, is the set of
nodes that need Φ functions, for each
variable

So we define DF[S], for a set of
flowgraph nodes S:
• DF[S] = ∪ DF[a]

# LLVM optimizations

## inline

## constant fold


## Reassociation

## Redundancy elimination optimization
remove redundant computations

Common RE opts are:
### value numbering

In SSA form, if x and a are variables,
they are congruent only if they are
both live and they are the same
variable

Or if they are provably the same value
(by constant or copy propagation)

#### Local (within block) value numbering

#### Global (within procedure) value numbering
- Embed use-def into the IR

### DCE

Aggressive mode: assume objects are dead until proven
otherwise, allowing dead objects with cycles to be deleted.


### conditional constant propagation
### common-subexpression elimination (CSE)
### partial-redundancy elimination


## DSA (Data Structure Analysis)

spends a negligible fraction of its time processing
the code representation itself, so its run times are not
indicative of the efficiency of the representation




## Common link-time optimizations

### (DGE) Dead global variable and function elimination

### DAE (aggressive Dead Argument and return value
Elimination)

### inline (a function integration pass)

# Function Calls and Exception Handling


LLVM code uses a runtime library for C++ ex-
ceptions support while exposing control-flow.

The runtime handles all of the implementation-specific details, such
as allocating memory for exceptions

the runtime functions manipulate the thread-local state of the excep-
tion handling runtime, but don’t actually unwind the stack.

Because the calling code performs the stack unwind, the op-
timizer has a better view of the control flow of the function
without having to perform interprocedural analysis.

For inlining, unwind target can be the same function as the unwinder.

## try/catch
Any function call within the try block becomes an
invoke. Any throw within the try-block becomes a call to
the runtime library followed by an
explicit branch to the appropriate catch block

The “catch block” then uses the C++ runtime library to determine if
the top-level current exception is of one of the types that is
handled in the catch block. If so, it transfers control to the
appropriate block, otherwise it calls unwind to continue un-
winding.

The runtime library handles the language-specific
semantics of determining whether the current exception is
of a caught type.

# Plain-text, Binary, and In-memory Representations

The LLVM representation is a first class language which
defines equivalent textual, binary, and in-memory (i.e., com-
piler’s internal) representations.

The instruction set serves as both:
1. a persistent, offline code representation
2. a compiler internal representation
There is no need of semantic conversions between the two.

# Representation Issues
## What value does type information provide?

LLVMincludes a flow-insensitive, field-sensitive and contextsensitive
points-to analysis called Data Structure Analysis
(DSA)

Several transformations in LLVM are based on
DSA, including Automatic Pool Allocation

As part of
the analysis, DSA extracts LLVM types for a subset of memory
objects in the program, using declared
types in the LLVMcode as speculative type information, and
checks conservatively whether memory accesses to an object
are consistent with those declared types


## How do highlevel features map onto LLVM?

Implicit calls (e.g. copy constructors) and parameters
(e.g. ‘this’ pointers) are made explicit.

Templates are fully instantiated by the C++ front
end before LLVM code is generated. (True polymorphic
types in other languages would be expanded
into equivalent code using non-polymorphic types in
LLVM.)

Base classes are expanded into nested structure types.
For this C++ fragment:
class base1 { int Y; };
class base2 { float X; };
class derived : base1, base2 { short Z; };
the LLVMtype for class derived is ‘{ {int}, {float},
short }’. If the classes have virtual functions, a vtable
pointer would also be included and initialized at
object allocation time to point to the virtual function
table

A virtual function table is represented as a global, con-
stant array of typed function pointers, plus the type-id
object for the class. With this representation, virtual
method call resolution can be performed by the LLVM
optimizer as effectively as by a typical source compiler
(more effectively if the source compiler uses only permodule
instead of cross-module pointer analysis).

C++ exceptions are lowered to the ‘invoke’ and
‘unwind’ instructions, exposing
exceptional control flow in the CFG. In fact,
having this information available at link time enables
LLVM to use an interprocedural analysis to eliminate
unused exception handlers. This optimization is much
less effective if done on a per-module basis in a sourcelevel
compiler.


# Installed binaries in /usr/local/bin

```bash
clang-installapi
find-all-symbols
ld64.lld
ld.lld
llc
lld
lldb
lldb-argdumper
lldb-dap
lldb-instr
lldb-server
lld-link
lli
llvm-addr2line
llvm-ar
llvm-as
llvm-bcanalyzer
llvm-bitcode-strip
llvm-cat
llvm-cfi-verify
llvm-config
llvm-cov
llvm-c-test
llvm-cvtres
llvm-cxxdump
llvm-cxxfilt
llvm-cxxmap
llvm-debuginfo-analyzer
llvm-debuginfod
llvm-debuginfod-find
llvm-diff
llvm-dis
llvm-dlltool
llvm-dwarfdump
llvm-dwarfutil
llvm-dwp
llvm-exegesis
llvm-extract
llvm-gsymutil
llvm-ifs
llvm-install-name-tool
llvm-jitlink
llvm-lib
llvm-libtool-darwin
llvm-link
llvm-lipo
llvm-lto
llvm-lto2
llvm-mc
llvm-mca
llvm-ml
llvm-modextract
llvm-mt
llvm-nm
llvm-objcopy
llvm-objdump
llvm-opt-report
llvm-otool
llvm-pdbutil
llvm-profdata
llvm-profgen
llvm-ranlib
llvm-rc
llvm-readelf
llvm-readobj
llvm-readtapi
llvm-reduce
llvm-remarkutil
llvm-rtdyld
llvm-sim
llvm-size
llvm-split
llvm-stress
llvm-strings
llvm-strip
llvm-symbolizer
llvm-tblgen
llvm-tli-checker
llvm-undname
llvm-windres
llvm-xray
```



# COMPILER ARCHITECTURE
Goal: enable sophisticated transformations at link-time, install-time, run-
time, and idle-time, by operating on the LLVM representation of a program at all stages.


