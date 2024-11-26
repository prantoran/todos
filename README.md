CMake Error at CMakeLists.txt:126 (message):
  llvm-gtest not found.  Please install llvm-gtest or disable tests with
  -DLLVM_INCLUDE_TESTS=OFF

build_llvm=`pwd`/llvm-project-llvmorg-19.1.3/build
build_clang=`pwd`/build-clang
installprefix=/usr/local
llvm=`pwd`/llvm-project-llvmorg-19.1.3
mkdir -p $build_llvm
mkdir -p $installprefix



cmake -G Ninja -S $llvm/clang -B $build_clang \
      -DLLVM_EXTERNAL_LIT=$build_llvm/utils/lit \
      -DLLVM_ROOT=$installprefix \
      -DLLVM_INCLUDE_TESTS=OFF
ninja -C $build_clang

https://fasterthanli.me/series/making-our-own-executable-packer/part-17

https://github.com/W4RH4WK/Debloat-Windows-10

https://www.doomedraven.com/2016/05/kvm.html

cmake -S llvm -B build -G Ninja \
	-DLLVM_INSTALL_UTILS=ON \
	-DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lldb;polly;cross-project-tests" \
	-DCMAKE_INSTALL_PREFIX=/usr/local \
	-DCMAKE_BUILD_TYPE=Release \
	-DLLVM_USE_LINKER=lld \
	-DLLVM_PARALLEL_COMPILE_JOBS=4 \
	-DLLVM_PARALLEL_LINK_JOBS=4 


# todos
https://volatilityfoundation.org/

## python

poetry



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
## macos
https://buaq.net/go-38839.html
https://www.sentinelone.com/labs/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/
## Build system
ninja
meson
## Linux
https://www.baeldung.com/linux/network-interface-configure
https://www.baeldung.com/linux/loopback-lo-device
https://askubuntu.com/questions/247625/what-is-the-loopback-device-and-how-do-i-use-it
https://developers.redhat.com/blog/2018/10/22/introduction-to-linux-interfaces-for-virtual-networking
https://www.devgem.io/posts/understanding-fread-and-handling-line-endings-in-c
https://dnsmasq.org/doc.html
### virtualbox
https://www.virtualbox.org/manual/ch09.html#changenat
usr/sbin/update-ca-certificates
cntlm NTP server
https://computer.howstuffworks.com/nat.htm
https://en.wikipedia.org/wiki/ACPI
https://en.wikipedia.org/wiki/Advanced_Programmable_Interrupt_Controller
https://www.baeldung.com/linux/dynamic-kernel-module-support
build-essential
inux-headers
NAT/PAT with nested KVM
SOCKS routing
Wireguard
https://remnux.org/
ufw firewall
https://wiki.linuxfoundation.org/networking/iproute2
https://medium.com/@eren.c.uysal/route-settings-linux-59e4353b6a9c#:~:text=The%20%2Fetc%2Fiproute2%2Frt_tables%20file%20is%20where%20IP%20routing%20tables,and%20use%20them%20to%20route%20different%20network%20traffic.
http://linux-ip.net/html/routing-tables.html
iptables vs netplan
https://linuxconfig.org/how-to-use-bridged-networking-with-libvirt-and-kvm
https://wiki.libvirt.org/Net.bridge.bridge-nf-call_and_sysctl.conf.html
https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html
https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux
https://dustinspecker.com/posts/iptables-how-kubernetes-services-direct-traffic-to-pods/
iptables
/etc vs /usr/local/etc
sed
ldconfig
https://www.baeldung.com/linux/hardware-enablement-hwe
https://dnsmasq.org/doc.html
### bridge network
Spanning Tree Protocol
### kvm
virsh vs virt-manager
#### virsh
https://wiki.archlinux.org/title/Libvirt#Using_polkit
how to connect to server/vm using ssh
https://documentation.ubuntu.com/server/how-to/virtualisation/libvirt/
https://askubuntu.com/questions/1129936/how-to-edit-the-etc-libvirt-libvirt-conf-file
https://www.libvirt.org/manpages/libvirtd.html
https://gitlab.com/apparmor/apparmor/-/wikis/Libvirt
https://www.libvirt.org/manpages/virtqemud.html\
https://sumit-ghosh.com/posts/virtualization-hypervisors-explaining-qemu-kvm-libvirt/
### terminal
https://dev.to/girordo/a-hands-on-guide-to-setting-up-zsh-oh-my-zsh-asdf-and-spaceship-prompt-with-zinit-for-your-development-environment-91n
https://www.linuxtechi.com/how-to-install-kvm-on-ubuntu/
### Network bridge
https://www.naturalborncoder.com/2014/10/understanding-tun-tap-interfaces/
https://linux.die.net/man/8/iptables
https://www.howtogeek.com/177621/the-beginners-guide-to-iptables-the-linux-firewall/
https://developers.redhat.com/articles/2022/04/06/introduction-linux-bridging-commands-and-features#
https://www.baeldung.com/linux/bridging-network-interfaces
https://wiki.linuxfoundation.org/networking/bridge
https://man7.org/linux/man-pages/man7/netlink.7.html
final distribution boards (FDBs), main distribution boards (MDBs), and virtual local area networks (VLANs)
ip link set tap_interface master bridge_interface
https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html
https://www.kernel.org/doc/html/latest/admin-guide/sysctl/net.html
#### virtual network veth0
https://superuser.com/questions/764986/howto-setup-a-veth-virtual-network
https://man7.org/linux/man-pages/man4/veth.4.html
### ip
https://baturin.org/docs/iproute2/
https://www.digitalocean.com/community/tutorials/how-to-use-iproute2-tools-to-manage-network-configuration-on-a-linux-vps
https://paulgorman.org/technical/linux-iproute2-cheatsheet.html
### tcpdump
https://linux.die.net/man/8/tcpdump
https://www.techtarget.com/searchnetworking/tutorial/How-to-capture-and-analyze-traffic-with-tcpdump
https://www.tcpdump.org/
#### nginx
http://nginx.org/en/docs/beginners_guide.html
### dev tools
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
