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
