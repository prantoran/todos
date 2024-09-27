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


# LLVM optimizations
## Reassociation

## Redundancy elimination



