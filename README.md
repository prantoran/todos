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

hardware-based trace cache

automatic pool allocation instead of garbage collection

# Linux
## bridge network
Spanning Tree Protocol

## kvm

virsh vs virt-manager

### virsh

how to connect to server/vm using ssh


## terminal
https://dev.to/girordo/a-hands-on-guide-to-setting-up-zsh-oh-my-zsh-asdf-and-spaceship-prompt-with-zinit-for-your-development-environment-91n

https://www.linuxtechi.com/how-to-install-kvm-on-ubuntu/



## Network bridge

https://linux.die.net/man/8/iptables

https://www.howtogeek.com/177621/the-beginners-guide-to-iptables-the-linux-firewall/

https://developers.redhat.com/articles/2022/04/06/introduction-linux-bridging-commands-and-features#

https://www.baeldung.com/linux/bridging-network-interfaces

https://wiki.linuxfoundation.org/networking/bridge

https://man7.org/linux/man-pages/man7/netlink.7.html

final distribution boards (FDBs), main distribution boards (MDBs), and virtual local area networks (VLANs)

### virtual network veth0
https://superuser.com/questions/764986/howto-setup-a-veth-virtual-network

https://man7.org/linux/man-pages/man4/veth.4.html

### tcpdump

https://linux.die.net/man/8/tcpdump

https://www.techtarget.com/searchnetworking/tutorial/How-to-capture-and-analyze-traffic-with-tcpdump

https://www.tcpdump.org/

### nginx

http://nginx.org/en/docs/beginners_guide.html

## dev tools

### tmux

https://hamvocke.com/blog/a-quick-and-easy-guide-to-tmux/

https://github.com/tmux/tmux/wiki/Getting-Started

## sources list

https://bash.cyberciti.biz/guide//etc/apt/sources.list_file

## cpp

stack frame of a function

https://blog.the-pans.com/cpp-exception-1/
https://gcc.gnu.org/wiki/LinkTimeOptimization

http://web.mit.edu/tibbetts/Public/inside-c/www/rtti.html

https://quuxplusone.github.io/blog/2021/02/15/devirtualization/

https://www.isi.deterlab.net/file.php?file=/share/shared/AnintroductiontoDwarf

gproc

compile-time, link-time (interprocedural), and runtime transformations for C and C++ programs

https://icps.u-strasbg.fr/~pop/gcc-ast.html#:~:text=Abstract%20Syntax%20Trees%20(or%20AST)%20are%20produced%20by%20each
https://gcc.gnu.org/projects/ast-optimizer.html#:~:text=GCC%2C%20in%20common%20with%20many%20other%20compilers%2C%20has,and%20is%20close%20to%20the%20generated%20assembly%20code.

setjmp/longjmp

## gdb

how to set a hardware read breakpoint at the bottom of the stack after the
pushad is executed
- the program will be interrupted when it performs a restore
operation using the popad instruction.
- HW break [ESP]

effect of step over the pushad instruction

Get EIP as OEP


## compiler

scalar, interprocedural, profile-driven, and some simple loop optimizations.

link time optimizations

cross-module pointer analysis

https://www.naukri.com/code360/library/partial-redundancy-elimination-in-compiler-design

https://www.cs.cornell.edu/courses/cs6120/2019fa/blog/sccp/

https://cr.openjdk.org/~cslucas/escape-analysis/EscapeAnalysis.html

https://www.cs.cornell.edu/courses/cs6120/2022sp/blog/type-alias/

https://www.brainkart.com/article/How-Cross-File-Optimization-Can-Be-Used-to-Improve-Performance_9409/

## research papers

### static analysis
https://dl.acm.org/doi/10.1145/2544137.2544151

### llvm

https://alibabatech.medium.com/gcc-vs-clang-llvm-an-in-depth-comparison-of-c-c-compilers-899ede2be378

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

ASLR



bound imports 

forwarder chain in image import descriptor

https://guidedhacking.com/threads/how-64-bit-programs-use-virtualprotect



## Rust

Ownership model

borrow checker

