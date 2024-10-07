# todos


## llvm
DWARF debugging information

https://llvm.org/pubs/2004-01-30-CGO-LLVM.html

https://llvm.org/docs/GarbageCollection.html


llvm type system 
custom memory allocation
non-type safe program constructs 
custom allocators


interprocedural analyses, such as a
context-sensitive points-to analysis (Data Structure Anal-
ysis [31]), call graph construction, and Mod/Ref analy-
sis, and interprocedural transformations like inlining, dead
global elimination, dead argument elimination, dead type
elimination, constant propagation, array bounds check elim-
ination [28], simple structure field reordering, automatic pool allocation


## cpp
gproc

compile-time, link-time (interprocedural), and runtime transformations for C and C++ programs

https://icps.u-strasbg.fr/~pop/gcc-ast.html#:~:text=Abstract%20Syntax%20Trees%20(or%20AST)%20are%20produced%20by%20each
https://gcc.gnu.org/projects/ast-optimizer.html#:~:text=GCC%2C%20in%20common%20with%20many%20other%20compilers%2C%20has,and%20is%20close%20to%20the%20generated%20assembly%20code.

setjmp/longjmp


## compiler

scalar, interprocedural, profile-driven, and some simple loop optimizations.

link time optimizations

cross-module pointer analysis

## research papers

### static analysis
https://dl.acm.org/doi/10.1145/2544137.2544151

### llvm

C. Lattner and V. Adve. Data Structure Analysis: A
Fast and Scalable Context-Sensitive Heap Analysis.
Tech. Report UIUCDCS-R-2003-2340, Computer
Science Dept., Univ. of Illinois at Urbana-Champaign,
Apr 2003.

C. Lattner and V. Adve. Automatic Pool Allocation
for Disjoint Data Structures. In Proc. ACM SIGPLAN
Workshop on Memory System Performance, Berlin,
Germany, Jun 2002.

## windows
https://www.ambray.dev/writing-a-windows-loader-part-3/

bound imports 

forwarder chain in image import descriptor

https://guidedhacking.com/threads/how-64-bit-programs-use-virtualprotect
