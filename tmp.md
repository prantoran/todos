
## Learning Roadmap (Weeks 1–4)  
Begin by strengthening your understanding of the key technologies involved. Dedicate the first month to study **FUSE**, **io_uring**, **Linux VFS**, the **QEMU storage (block) layer**, and general **asynchronous I/O** patterns in Linux. Use this time to read documentation, review example code, and experiment with small programs to internalize concepts:

- **Filesystem in Userspace (FUSE)** – Learn how the kernel forwards filesystem operations to a userspace daemon. FUSE allows implementing a filesystem in user space via a kernel module that acts as a bridge to kernel interfaces ([Filesystem in Userspace - Wikipedia](https://en.wikipedia.org/wiki/Filesystem_in_Userspace#:~:text=Filesystem%20in%20Userspace%20,to%20the%20actual%20kernel%20interfaces)). This means file operations (open, read, write, etc.) from processes are handed by the kernel VFS to the FUSE module, which then communicates with a user-space handler program. **Tasks/Resources:**  
  - Read the [FUSE Wikipedia](https://en.wikipedia.org/wiki/Filesystem_in_Userspace) article and kernel documentation to understand the basic architecture. The figure below illustrates how a user-space process (left) making a request (e.g. `ls -l /tmp/fuse`) triggers the kernel’s VFS to call into the FUSE driver, which then passes the request to a user-space filesystem daemon (right) that implements the actual operation ([Filesystem in Userspace - Wikipedia](https://en.wikipedia.org/wiki/Filesystem_in_Userspace#:~:text=ImageA%20flow,that%20originally%20made%20the%20request)). This round-trip explains the extra context switches and overhead in FUSE.  
   ([Filesystem in Userspace - Wikipedia](https://en.wikipedia.org/wiki/Filesystem_in_Userspace#:~:text=ImageA%20flow,that%20originally%20made%20the%20request)) ([image]()) *Figure: FUSE architecture – the kernel module (green) forwards VFS calls from applications to a user-space handler via /dev/fuse, incurring context switches.*  
  - Install **libfuse3** on your system and try a simple FUSE example (for instance, the “hello world” filesystem from libfuse). Observe how mounting a FUSE filesystem involves running a userspace daemon. Use `strace` to trace system calls and see the communication over `/dev/fuse`.  
  - Understand the performance implications. Each filesystem operation in FUSE typically involves at least two context switches (user→kernel and back) plus data copying overhead. Read the Linux kernel mailing list discussion or patch notes on *fuse-over-io_uring* for performance motivation – the goal is to reduce context switches by using shared memory and batched syscalls ([fuse: fuse-over-io-uring [LWN.net]](https://lwn.net/Articles/997400/#:~:text=Motivation%20for%20these%20patches%20is,uring%2C%20but%20through%20ioctl%20IOs)) ([fuse: fuse-over-io-uring [LWN.net]](https://lwn.net/Articles/997400/#:~:text=This%20cache%20line%20bouncing%20should,for%20example%20either%20with%20IORING_SETUP_SQPOLL)). These notes explain that fuse-over-io_uring will avoid bouncing requests between cores and cut the number of kernel/user context switches roughly in half by consolidating request submission and completion into one step ([fuse: fuse-over-io-uring [LWN.net]](https://lwn.net/Articles/997400/#:~:text=This%20cache%20line%20bouncing%20should,for%20example%20either%20with%20IORING_SETUP_SQPOLL)).  

- **io_uring** – Study Linux’s modern asynchronous I/O interface. io_uring (introduced in Linux 5.1) uses shared ring buffers between user space and the kernel to submit and complete I/O without a syscall per operation ([Optimizing Proxmox: iothreads, aio, & io_uring | Blockbridge Knowledgebase](https://kb.blockbridge.com/technote/proxmox-aio-vs-iouring/#:~:text=Io,without%20serializing%20QEMU%E2%80%99s%20centralized%20scheduler)). It is designed for higher performance than older Linux AIO (which had limitations and could block for certain I/O) ([io_uring by example: Part 1 – Introduction – Unixism](https://unixism.net/2020/04/io-uring-by-example-part-1-introduction/#:~:text=processes%20or%20threads,interface)) ([Features/IOUring - QEMU](https://wiki.qemu.org/Features/IOUring#:~:text=io_uring%20is%20a%20Linux%20API,AIO%20API%20that%20QEMU%20supports)). **Tasks/Resources:**  
  - Read an introductory blog or the `io_uring` man page to learn how it works. In brief, an io_uring instance sets up two circular ring buffers in shared memory: a **submission queue (SQ)** that the application fills with I/O requests, and a **completion queue (CQ)** that the kernel uses to post completions ([Why you should use io_uring for network I/O | Red Hat Developer](https://developers.redhat.com/articles/2023/04/12/why-you-should-use-iouring-network-io#:~:text=,user%20space%20and%20the%20kernel)). The figure below shows this mechanism: the application adds requests to the tail of the SQ, the kernel picks them up and processes them, then writes results to the CQ for the application to read ([Why you should use io_uring for network I/O | Red Hat Developer](https://developers.redhat.com/articles/2023/04/12/why-you-should-use-iouring-network-io#:~:text=,I%2FO%C2%A0operations%20back%20to%20user%20space)).  
   ([Why you should use io_uring for network I/O | Red Hat Developer](https://developers.redhat.com/articles/2023/04/12/why-you-should-use-iouring-network-io#:~:text=,user%20space%20and%20the%20kernel)) ([Why you should use io_uring for network I/O | Red Hat Developer](https://developers.redhat.com/articles/2023/04/12/why-you-should-use-iouring-network-io)) *Figure: io_uring uses shared memory ring buffers for async I/O. The app adds requests to the Submission Queue tail, the kernel consumes them and posts results to the Completion Queue. This avoids per-I/O syscalls by batching work in memory.*  
  - Try a small C program using **liburing** to solidify your understanding. For example, write a program that reads a file using io_uring instead of `read()`. This will familiarize you with submission queue entries (SQEs) and completion queue entries (CQEs).  
  - Read about advanced io_uring features like submission polling and fixed buffers, since these might relate to performance optimizations for FUSE. (You don’t need to master them immediately, but be aware of them.)  

- **Linux VFS (Virtual File System)** – The VFS is the kernel layer that provides a common file operation interface to user programs, abstracting different filesystems. It’s “the glue between user requests and filesystem-specific implementations” ([Introduction to the Linux Virtual Filesystem (VFS): A High-Level Tour — Star Lab Software](https://www.starlab.io/blog/introduction-to-the-linux-virtual-filesystem-vfs-part-i-a-high-level-tour#:~:text=The%20Linux%20variant%20of%20this,coexist%20in%20a%20unified%20namespace)) ([Introduction to the Linux Virtual Filesystem (VFS): A High-Level Tour — Star Lab Software](https://www.starlab.io/blog/introduction-to-the-linux-virtual-filesystem-vfs-part-i-a-high-level-tour#:~:text=The%20VFS%20is%20sandwiched%20between,From%20a%20high)). A solid grasp of VFS will help you understand how FUSE hooks into the kernel. **Tasks/Resources:**  
  - Read high-level overviews of the Linux VFS (for example, “Overview of the Linux VFS” in kernel docs or a relevant LWN article). Key concepts include superblocks, inodes, dentries, file operations, and how system calls like `open()` and `read()` traverse the VFS before reaching a specific filesystem driver.  
  - Focus on how VFS interacts with FUSE: for instance, when an open/read happens on a FUSE mount, VFS calls the FUSE driver’s `->open` or `->read` implementation, which then enqueues a request to the FUSE user daemon. Understanding this flow will clarify where the io_uring-based mechanism will plug in.  
  - If possible, glance at the Linux source (`fs/fuse/` directory) to see how FUSE requests are queued and how the ioctl or `read()/write()` on `/dev/fuse` works. You don’t need to absorb every detail, but mapping out the call flow will help when implementing changes.  

- **QEMU Block Layer & Virtio-FS** – Familiarize yourself with QEMU’s storage architecture, as well as how virtio-fs is implemented. The QEMU **block layer** handles virtual disks and files: it supports many backends (raw files, qcow2, network storage, etc.) and performs asynchronous I/O via an event loop and threads. QEMU can use Linux AIO or io_uring as the async engine for disk I/O ([](https://kvm-forum.qemu.org/2020/KVMForum_2020_io_uring_passthrough_Stefano_Garzarella.pdf#:~:text=%E2%97%8F%20QEMU%205,IORING_OP_WRITEV%20%E2%97%8F%20IORING_OP_READV%20%E2%97%8F%20IORING_OP_FSYNC)). **Tasks/Resources:**  
  - Read QEMU’s documentation on its block layer (for example, “QEMU Block Drivers” and Stefan Hajnoczi’s blog posts or slides on QEMU block layer concepts). Understand terms like **AioContext**, **BlockDriverState**, and how QEMU dispatches I/O requests from a virtual device (e.g., virtio-blk or virtio-fs) to the host. QEMU 5.0 added support for io_uring as an AIO backend, used via `-drive aio=io_uring` in VM options ([](https://kvm-forum.qemu.org/2020/KVMForum_2020_io_uring_passthrough_Stefano_Garzarella.pdf#:~:text=%E2%97%8F%20QEMU%205,IORING_OP_WRITEV%20%E2%97%8F%20IORING_OP_READV%20%E2%97%8F%20IORING_OP_FSYNC)) ([Features/IOUring - QEMU](https://wiki.qemu.org/Features/IOUring#:~:text=io_uring%20is%20an%20alternative%20AIO,drive%20aio%3Dio_uring)). This indicates QEMU already has some io_uring integration in its block subsystem, which is a useful reference for integrating io_uring with FUSE.  
  - Learn how **virtio-fs** works. Virtio-fs uses a vhost-user backend (a separate process called **virtiofsd**) that implements a FUSE server. The guest VM communicates with virtiofsd (over a Unix domain socket) to perform file operations on a shared host directory. Most virtio-fs code runs in this userspace daemon, not inside QEMU itself ([virtiofs - shared file system for virtual machines / Standalone usage](https://virtio-fs.gitlab.io/howto-qemu.html#:~:text=QEMU%204,in%20virtiofsd%20instead%20of%20QEMU)) ([virtiofs - shared file system for virtual machines / Standalone usage](https://virtio-fs.gitlab.io/howto-qemu.html#:~:text=Building%20virtiofsd)). Knowing this, plan to familiarize yourself with virtiofsd’s code as well (see below).  
  - **Browse the virtiofsd source**: The legacy C version of virtiofsd was included in QEMU’s source (`tools/virtiofsd`), but has been replaced by a Rust implementation ([
      FS#76352 : [qemu] Consider replacing qemu-virtiofsd with new Rust version
    ](https://bugs.archlinux.org/task/76352#:~:text=,and%20moving%20should%20be%20simple)). New development (like FUSE over io_uring) likely targets the Rust virtiofsd. Even if you haven’t used Rust before, skim the virtiofsd repository (gitlab.com/virtio-fs/virtiofsd) to see how it handles FUSE requests (look for where `/dev/fuse` is read/written). This will hint at how to integrate io_uring—perhaps by using the new **IORING_OP_URING_CMD** operation in place of read/write on the fuse device ([fuse: fuse-over-io-uring [LWN.net]](https://lwn.net/Articles/997400/#:~:text=This%20adds%20support%20for%20uring,are%20still%20to%20be%20expected)). You might also read the **libfuse** documentation, since virtiofsd uses libfuse to simplify FUSE protocol handling.  

- **Asynchronous I/O Patterns in Linux** – Since this project is about asynchronous I/O, review how Linux handles async operations traditionally vs. with io_uring. **Tasks/Resources:**  
  - Compare classic **blocking I/O**, **multi-threading**, **non-blocking with epoll**, and **Linux AIO (io_submit)**. For example, QEMU historically offered `aio=threads` (which delegates I/O to a thread pool) and `aio=native` (Linux AIO) for disk I/O. Each approach has trade-offs in latency and throughput.  
  - Read an article on why Linux’s older AIO was insufficient (e.g. it only worked with O_DIRECT and still had system call overhead for completions ([io_uring by example: Part 1 – Introduction – Unixism](https://unixism.net/2020/04/io-uring-by-example-part-1-introduction/#:~:text=processes%20or%20threads,interface))). This context will highlight how io_uring’s design (submission/completion rings) is superior in avoiding kernel transitions ([Optimizing Proxmox: iothreads, aio, & io_uring | Blockbridge Knowledgebase](https://kb.blockbridge.com/technote/proxmox-aio-vs-iouring/#:~:text=Io,without%20serializing%20QEMU%E2%80%99s%20centralized%20scheduler)).  
  - Understand **io_uring in the kernel**: The new `IORING_OP_URING_CMD` was introduced to let subsystems (like FUSE) use io_uring as a transport. Essentially, the FUSE driver can register an io_uring command with the kernel, so that FUSE user daemons can submit requests via an io_uring interface rather than reading /dev/fuse ([fuse: fuse-over-io-uring [LWN.net]](https://lwn.net/Articles/997400/#:~:text=This%20adds%20support%20for%20uring,are%20still%20to%20be%20expected)). For deeper insight, you can read the fuse-over-io_uring RFC patch cover letter on the linux-fsdevel list ([fuse: fuse-over-io-uring [LWN.net]](https://lwn.net/Articles/997400/#:~:text=Motivation%20for%20these%20patches%20is,uring%2C%20but%20through%20ioctl%20IOs)), which explains the motivation and approach. In short, *fuse-over-io_uring* uses shared buffers and avoids separate read/write syscalls for each FUSE message, aiming to significantly reduce context switch overhead and cache line bouncing between kernel and user ([fuse: fuse-over-io-uring [LWN.net]](https://lwn.net/Articles/997400/#:~:text=This%20cache%20line%20bouncing%20should,for%20example%20either%20with%20IORING_SETUP_SQPOLL)).  
  - As an exercise, diagram the difference between the current FUSE workflow and the proposed io_uring workflow. This will help you internalize what you’ll implement. The current workflow: **guest I/O -> virtiofsd -> libfuse -> /dev/fuse (read request, process, write reply) -> kernel**. The new workflow will replace the read/write on /dev/fuse with submitting an SQE and getting a CQE, which should be faster.  

By the end of the first 3–4 weeks, you should be comfortable with these concepts. You don’t need to have mastered everything, but you should know how pieces fit together (for instance, what part of the stack each technology occupies, and how data flows when a guest reads a file from a virtio-fs share). Keep notes of important resources or references as you’ll refer back during implementation. 

## Development Environment Setup (Week 1)  
Setting up a robust development environment on your Ubuntu 24.04 LTS machine is crucial. This includes installing all dependencies, building QEMU from source, and preparing tools for editing and debugging. Follow these steps to configure your environment:

1. **System Update and Required Packages:** Update your system and install general build tools. You’ll need Git, a C compiler (gcc/clang), Python3, and others. On Ubuntu/Debian, a convenient way is:  
   ```bash
   sudo apt update && sudo apt install build-essential git python3 pkg-config ninja-build meson libglib2.0-dev
   ```  
   (Ubuntu 24.04 may already include Meson and Ninja; if not, this command installs them. Meson is QEMU’s build system generator and Ninja will compile the code.)  

2. **QEMU Build Dependencies:** Install all libraries that QEMU may require. QEMU has many optional features; for our purposes, we need at least **GLib 2.x**, **Pixman**, **zlib**, **SDL2** (if you want graphical output), **liburing**, and **libfuse**. The QEMU docs recommend using your package manager to get build deps:  
   ```bash
   sudo apt build-dep qemu
   ```  
   This will pull in the necessary development libraries for the QEMU version packaged in Ubuntu ([Setup build environment — QEMU  documentation](https://www.qemu.org/docs/master/devel/build-environment.html#:~:text=You%20first%20need%20to%20enable,use%20apt%20to%20install%20dependencies)). Additionally, verify the following are installed, as they are specifically relevant:  
   - **liburing-dev** – to enable io_uring support in QEMU (for block I/O and our fuse project)  
   - **libfuse3-dev** – to enable FUSE-related features. QEMU’s configure has an `--enable-fuse` flag to build FUSE block exports ([QEMU Storage Daemon - DEV Community](https://dev.to/amarjargal/qemu-storage-daemon-nm9#:~:text=sudo%20apt%20install%20libfuse3)), which requires libfuse3. Even if working with virtiofsd separately, having this allows you to experiment with QEMU’s FUSE export feature as well.  
   - **libaio-dev**, **libcap-ng-dev**, **libattr1-dev** – (optional, for Linux AIO, security, etc., often included by build-dep).  
   - **Meson and Ninja** – as noted, ensure you have recent versions (Meson ≥0.61). Ubuntu 24.04 should have a new enough Meson, but if not, you can `pip3 install --user meson ninja`.  

3. **Cloning QEMU Source:** Fetch the QEMU source code from the official repository. It’s recommended to work with the latest upstream (`master` branch) for GSoC projects:  
   ```bash
   git clone https://gitlab.com/qemu-project/qemu.git
   cd qemu
   git submodule update --init --recursive
   ```  
   Using the latest code ensures you have any recent virtio-fs or io_uring improvements (and fewer merge conflicts later). The submodule command pulls dependencies like edk2 (for firmware), which might not be strictly needed for our work but it’s good practice.  

4. **Configuring the Build (Meson):** Create a build directory and configure QEMU. For development, enable debug symbols and disable optimizations for easier debugging. Also, include options relevant to our project:  
   ```bash
   mkdir build && cd build
   meson setup -Dbuildtype=debug -Dfuse_export=enabled -Ddebug-info=enabled -Doptimization=0 \
               -Ddefault_library=static ..
   ```  
   Some notes: the `-Dfuse_export=enabled` corresponds to `--enable-fuse` in the old configure script (enables QEMU’s FUSE block export) ([QEMU Storage Daemon - DEV Community](https://dev.to/amarjargal/qemu-storage-daemon-nm9#:~:text=sudo%20apt%20install%20libfuse3)). This isn’t directly for virtio-fs, but it compiles in code that may be informative and is a good sanity check that libfuse is found. We also request static libraries to simplify profiling (optional). Meson will detect liburing and enable io_uring support automatically if found; watch the output to make sure it says “io_uring support: YES”. If it says NO, install/update **liburing-dev** and re-run meson.  

5. **Building QEMU:** Compile the code using Ninja:  
   ```bash
   ninja -C build -j$(nproc)
   ```  
   This will take a while on first build (QEMU is large). With a multi-core CPU and enough RAM (see Hardware section), you can parallelize with `-j`. After it finishes, you should have QEMU binaries (e.g. `build/qemu-system-x86_64`). You can run `build/qemu-system-x86_64 --version` to confirm the build was successful. 

6. **Setting Up virtiofsd (if needed):** Since virtiofsd (the FUSE daemon for virtio-fs) is a separate project in Rust, you’ll want to set that up too, as our feature likely involves modifying it:  
   - Install Rust toolchain (via `rustup`) if not already available. Rust 1.60+ should be fine.  
   - Clone the virtiofsd repo:  
     ```bash
     git clone https://gitlab.com/virtio-fs/virtiofsd.git
     cd virtiofsd
     cargo build --release
     ```  
   - This produces `target/release/virtiofsd`. We’ll use this binary to test virtio-fs. (If building or modifying virtiofsd, you can run `cargo build` without `--release` to get a debug build which is easier to debug).  
   *Note:* The Rust virtiofsd is now the primary, but if you or your mentors prefer working with the older C virtiofsd (which might be simpler C but is deprecated ([
      FS#76352 : [qemu] Consider replacing qemu-virtiofsd with new Rust version
    ](https://bugs.archlinux.org/task/76352#:~:text=,and%20moving%20should%20be%20simple))), you can find it in QEMU 7.2 sources. However, focusing on the Rust version is future-proof. If you go this route, allocate some time to learn basic Rust syntax and how FFI works, since you might need to call io_uring syscalls from Rust.  

7. **IDE / Editor Configuration:** Choose a development environment that makes navigating QEMU’s large codebase manageable. Popular options: 
   - **VS Code** with the C/C++ extension (configure IntelliSense include paths to the QEMU source and build directories for autocompletion). You can use **clangd** or **ccls** language servers for smarter code navigation.  
   - **CLion** (if available) or **Eclipse CDT** can index the code and help with refactoring, though they may need a compile_commands.json from Meson (`meson compile -C build --compile_commands`).  
   - Even a good text editor (Vim/Emacs) with ctags or LSP can suffice. Ensure you generate tags or an index for quick “go to definition” since you’ll be jumping between QEMU, kernel headers, and perhaps virtiofsd code frequently.  
   - Install **GDB** for debugging. With QEMU built in debug mode, you can step through code or inspect crashes. VS Code can be configured to launch QEMU under GDB for instance.  
   - It’s also useful to familiarize yourself with QEMU’s coding style and guidelines. Read `docs/devel/style.rst` in QEMU to follow their C formatting conventions and commit message norms. You can use QEMU’s `scripts/checkpatch.pl` on your patches to catch style issues early.  

8. **KVM Access:** Since you’ll be running VMs for testing, ensure KVM is enabled on your host. Verify that `/dev/kvm` exists and your user has permission (you may need to add yourself to the `kvm` group or run QEMU with sudo if not set). KVM will accelerate the guest significantly, which is important for realistic I/O performance testing. If for some reason KVM is not available, you can use TCG (software emulation), but it will be much slower and could bottleneck CPU during I/O benchmarks.  

9. **Version Control Workflow:** Use Git effectively. Create a new branch for your GSoC work (e.g. `gsoc-fuse-io_uring`). Commit early and often with clear messages. This way you can experiment freely and also revert or bisect if something breaks. It also makes it easier to send patches later. Consider pushing your branch to a personal fork on GitLab/GitHub regularly as a backup and for your mentor to review progress.  

By the end of Week 1, you should have QEMU and virtiofsd built from source and an editor setup you’re comfortable with. This foundation will allow you to quickly prototype and test code changes in the following weeks.

## Build and Testing Pipeline (Weeks 2–3)  
With the environment ready, the next step is establishing a reliable build and test workflow. You will be frequently rebuilding QEMU/virtiofsd and launching VMs to test your changes, so streamline this process:

- **Rebuilding Quickly:** After the initial full build, incremental builds are much faster. When you edit QEMU C code, just run `ninja -C build` again – Meson/Ninja will compile only changed files and relink. For virtiofsd (Rust), `cargo build` will likewise incrementally build. It’s a good idea to compile with debug symbols throughout development. Optimized builds can be done later for benchmarking. Keep an eye on compiler warnings and fix them early. Enable extra warnings (`-Dwarning_level=1` in Meson, which QEMU uses by default) to catch potential issues.  

- **Running a QEMU VM:** To test FUSE/virtiofsd functionality, prepare a small Linux virtual machine image: for example, an Ubuntu Server or Alpine Linux image for the guest. You can use cloud images or create one with `qemu-img` and install an OS. Ensure the guest kernel is relatively new (5.15+ or newer) so it has virtio-fs support (kernel 5.4+ has virtiofs). The guest OS should have the `virtiofs` kernel module available (most modern distributions do).  

  A basic command to boot a VM (with 2 GB RAM, 2 CPUs) is:  
  ```bash
  build/qemu-system-x86_64 -m 2048 -smp 2 -enable-kvm -cpu host \
      -drive file=guest.img,format=qcow2,if=virtio \
      -nographic -serial mon:stdio -kernel bzImage -append "console=ttyS0 root=/dev/vda1 rw"
  ```  
  (Replace `guest.img` with your disk image, and `bzImage` with a kernel image if you prefer using -kernel). This boots a console-only VM which is useful for automated testing. Ensure you can log into the guest.  

- **Setting up Virtio-FS testing:** Now, to test the virtiofs feature (which is the crux of our project), you will launch **virtiofsd** on the host and attach it to the QEMU VM:  
  1. **Prepare a shared directory** on the host, e.g. `mkdir ~/shared_test` and put a few test files in it (this will be exported to the guest).  
  2. **Start virtiofsd** (the one you built or installed). For example:  
     ```bash
     ./virtiofsd --socket-path=/tmp/vhostqemu --shared-dir=/home/user/shared_test --cache=auto &
     ```  
     This command may differ slightly based on virtiofsd version. The old syntax (C version) was `-o source=/path -o cache=always`, whereas the Rust version uses `--shared-dir` and `--cache`. The `--socket-path` specifies a Unix socket that QEMU will use to communicate (here `/tmp/vhostqemu`). Keep virtiofsd running in a separate terminal.  

  3. **Launch QEMU with virtio-fs device**. You need to pass the socket to QEMU and add a *vhost-user FS* device:  
     ```bash
     build/qemu-system-x86_64 -enable-kvm -m 2048 -cpu host -smp 2 \
       -object memory-backend-memfd,id=mem,size=2048M,share=on \
       -numa node,memdev=mem \
       -chardev socket,id=char0,path=/tmp/vhostqemu \
       -device vhost-user-fs-pci,chardev=char0,tag=myfs \
       -drive file=guest.img,format=qcow2,if=virtio ...
     ```  
     Let’s break down the important options:  
     - The `-chardev socket,id=char0,path=/tmp/vhostqemu` connects QEMU to the virtiofsd’s socket.  
     - The `-device vhost-user-fs-pci,...,tag=myfs` adds a virtio-fs device in the guest. `tag=myfs` is an identifier for the mount.  
     - The `-object memory-backend-memfd,...share=on` part allocates shared memory for DAX (Direct Access). While not strictly required for basic functionality, it’s recommended to include `share=on` so that virtiofsd and QEMU share the file pages (this is for performance with cache=auto/always).  
     - Ensure the guest kernel command-line includes support for huge memory if using DAX, or simply omit the `-object` and `-numa` lines if you want to start without DAX initially.  

     *Note:* The above is a typical setup based on virtio-fs documentation ([virtiofs - shared file system for virtual machines / Standalone usage](https://virtio-fs.gitlab.io/howto-qemu.html#:~:text=qemu,drive%20if%3Dvirtio%2Cfile%3Drootfsimage.qcow2)). Adjust paths and sizes as needed. Once QEMU boots with these options, log into the guest and **mount the virtio-fs** filesystem:  
     ```bash
     mkdir /mnt/hostshare  
     mount -t virtiofs myfs /mnt/hostshare
     ```  
     Now `/mnt/hostshare` in the guest should show the contents of `~/shared_test` from the host. Test it by creating or editing files from both sides. This confirms that virtiofsd and QEMU are working together.  

- **Testing Baseline Behavior:** Before making any changes, it’s important to have a baseline. Run simple I/O tests on the shared filesystem *as it is now*. For example, in the guest:  
  - Copy a large file (`dd if=/dev/zero of=/mnt/hostshare/test.bin bs=1M count=500`) and note the throughput.  
  - Run `fio` (if installed in guest) on `/mnt/hostshare` with a mix of reads and writes.  
  - Observe CPU usage: run `top` or `pidstat` on the host to see how much CPU `virtiofsd` is using and how much system vs user time is spent (this will be useful to compare after improvements).  

  This baseline testing not only verifies your setup but also gives you a reference point for later benchmarking. 

- **Automated Testing & QEMU’s Tests:** QEMU has an extensive testsuite (unit tests, functional tests, etc., some using the Avocado framework). For our project, relevant tests might be under `tests/qtest/` or integration tests for virtio-fs. Run `ninja -C build check` to execute QEMU’s built-in tests ([Features/IOUring - QEMU](https://wiki.qemu.org/Features/IOUring#:~:text=How%20to%20use%20it)) – ensure they pass in your environment to confirm everything is built correctly. If there are specific virtio-fs tests (for example, look for any scripts in `tests/avocado/` related to virtiofs), try running those. This can catch regressions if you introduce a bug later.  

- **Debugging Tools:** If the VM or virtiofsd crashes during testing, use GDB to debug. For instance, you can start QEMU under GDB with:  
  ```bash
  gdb --args build/qemu-system-x86_64 -enable-kvm -m 2048 ... (rest of args)
  ```  
  and then use breakpoints or `run` until crash to get a backtrace. Similarly, you can debug virtiofsd by running `gdb --args virtiofsd ...args...`. Being comfortable with stepping through code in GDB will help when you start modifying complex logic.  

- **Iterative Development:** Going forward, each time you implement a part of the FUSE-over-io_uring feature, you will:  
  - Rebuild QEMU or virtiofsd (depending on where the change is),  
  - Re-run the virtiofsd daemon and QEMU VM as above,  
  - Mount the share in the guest and execute test operations (like reading/writing files),  
  - Verify correct behavior (no errors in dmesg or crashes), and measure performance if applicable.  

  To speed up the cycle, automate where possible. You can write a small shell script to launch virtiofsd and QEMU with the desired parameters. For example, a script `run_vm.sh` that kills any previous virtiofsd, starts a new one, then launches QEMU with one command. This way you avoid typing long commands each time.  

- **Testing edge cases:** In addition to normal reads/writes, test things like creating many small files, metadata-heavy operations (e.g., `find . -type f` on the shared directory), unmounting and remounting, etc. This helps ensure your changes don’t break less common operations. Keep an eye on the console output of virtiofsd; add verbose logging (virtiofsd usually has a `-d` debug flag) to see the sequence of FUSE requests and responses. This will be invaluable when you switch to the io_uring mode – you can compare that the functional behavior is the same.  

Establishing this build-and-test routine early (by Week 3) will make the development phase much smoother. You’ll be confident that you can quickly try out changes and verify them, which is key in an open-source project where rapid iteration and feedback are the norm.

## Benchmarking and Profiling Pipeline (Weeks 5–8)  
Once you begin implementing the “FUSE over io_uring” feature, you will need to measure its impact and ensure it meets performance goals. Set up a benchmarking and profiling strategy to collect data **before and after** your changes:

- **Select Benchmark Tools and Metrics:** For filesystem and I/O performance, **fio** is an excellent tool ([Performance benchmarking with Fio on Nutanix](https://portal.nutanix.com/kb/12075#:~:text=Fio%20is%20a%20benchmarking%20and,layer%20of%20the%20Linux%20kernel)). It can generate read/write workloads with various block sizes, queue depths, and patterns (random vs sequential). Plan a few representative fio jobs to simulate workloads: e.g., sequential 4MB writes (to measure throughput), random 4KB reads (to measure IOPS and latency), and mixed read/write. You can run fio inside the guest targeting the virtio-fs mount, or on the host against the FUSE export (though guest view is more realistic). Key metrics to collect: I/O **throughput** (MB/s), **IOPS**, and **latency** (mean and tail latencies).  

- **Establish Baseline Performance:** Before enabling io_uring in FUSE, run these fio workloads on the baseline system. Save the results (throughput, IOPS, latency) for comparison. Also note CPU usage during the run: how much CPU % does `virtiofsd` consume? Does it saturate a single core? How many context switches are happening? You can use `perf stat` on the virtiofsd process to count context-switches, CPU cycles, instructions, etc., and `perf record -g` to profile where time is spent. For example:  
  ```bash
  perf stat -e context-switches,cycles,instructions -p $(pidof virtiofsd) sleep 30
  ```  
  while fio runs, to get an overview of switches and CPU usage. Later, you’ll do the same after your changes to see the difference (ideally, context switches should drop and perhaps cycles per operation too).  

- **Implement & Benchmark Iteratively:** When you have an initial implementation of FUSE over io_uring (even a partial one), run the same benchmarks. Don’t wait until the project is “complete” – test early versions to verify you’re actually getting improvement. If the performance isn’t as expected, use profiling to investigate. For example:  
  - Run `perf top` or `perf record` on virtiofsd to see where it spends CPU. With io_uring, ideally less time is spent in kernel context-switch or read/write syscalls. If you still see a lot of time in `read()` or `write()`, maybe your io_uring path isn’t being used as intended.  
  - Use `strace -c -p $(pidof virtiofsd)` to summarize syscalls during a benchmark. In baseline, you’ll see lots of `read(fdFuse)` and `write(fdFuse)` calls. In the io_uring version, you expect far fewer of those (maybe replaced by `io_uring_enter` calls if any). This is a quick sanity check.  

- **Compare Results and Identify Regressions:** Create a small report of baseline vs new performance. For each test scenario, note the improvement (or any regressions). For instance, you might find sequential throughput improves modestly, but latency for small ops improves significantly due to fewer context switches. If something regresses (e.g., maybe CPU usage went up or a certain pattern got slower), profile that case to understand why. It could indicate a bug or an area for optimization (for example, maybe the io_uring submission isn’t batching as hoped).  

- **Use Kernel Tracing if Needed:** To deeply understand what’s happening, you can use ftrace or `trace-cmd` on the host. Enabling events like `fuse:*` or `io_uring:*` can show timing of events. For example, trace how long a FUSE request sits in the queue. This can help demonstrate that with io_uring, the wait time is reduced. However, use tracing only if needed, as it can be complex; often perf and logs will suffice.  

- **Memory and Threading Considerations:** While benchmarking, observe if the new method affects memory usage or CPU concurrency. For example, does virtiofsd with io_uring use more memory for buffers? Is it utilizing multiple cores better (or worse) than before? Tools like `htop` can show if virtiofsd is multi-threaded and using multiple CPUs (virtiofsd can use a thread pool for parallel requests). Ensure your benchmarks cover both single-threaded and multi-threaded access to the FS (e.g., fio with `numjobs=4` to simulate 4 threads doing I/O). 

- **Benchmarking QEMU Block vs Virtio-FS (Optional):** For additional context, you might compare virtio-fs performance to virtio-blk or virtio-9p in similar scenarios. This isn’t directly required, but it can be useful to see how close virtio-fs (with your improvements) comes to, say, a direct virtio-blk raw disk in throughput or latency. It gives a sense of how much overhead remains.  

- **Long-Run Stability Tests:** Before finalizing changes, run longer tests (several minutes or more) to catch any resource leaks or stability issues under load. Also test with different caching modes (`cache=none` vs `cache=auto` in virtiofsd) because io_uring might have different effects depending on whether DAX or page cache is in use. Make sure that under heavy load your implementation doesn’t deadlock or crash. Using tools like **Valgrind** on virtiofsd (if using the C version) or Rust’s `cargo test` (for the Rust version) can help catch memory errors.  

- **Documenting Performance:** As you gather results, document them in a log or report. This will be very useful when communicating with the QEMU community – performance patches are always scrutinized to ensure they deliver benefits. Having clear before-and-after numbers and charts will bolster your patch submission. It also helps you track progress during GSoC (e.g., by mid-term, show a small improvement, by final, show the full improvement).  

By Week 8, you should have a solid setup to quantify your work. Regularly running benchmarks will guide optimizations and verify that you’re on the right track. Remember, the goal of this project is performance **and** correctness – so use profiling not only to speed things up but also to ensure you’re not inadvertently adding latency or CPU overhead elsewhere.

## Hardware Recommendations for Development & Testing  
Working on QEMU and running multiple VMs can be resource-intensive. A capable development machine will make your 2-month effort much more pleasant. Here are our hardware recommendations for smooth compiling, debugging, and benchmarking:

- **CPU:** A multi-core processor is important. Aim for at least a **quad-core** CPU (Intel i5/i7 or AMD Ryzen 5/7 class). More cores (6, 8, or even 16) will speed up compilation (Ninja can parallelize builds) and allow you to dedicate cores to the guest VM and virtiofsd. For example, with 8 cores you could pin the guest to 4 and leave 4 for the host/virtiofsd to avoid contention. Also, ensure the CPU supports virtualization extensions (Intel VT-x or AMD-V) so you can use KVM. Virtio-fs performance in a TCG (no-KVM) environment is dramatically lower, so KVM is highly recommended.  

- **Memory (RAM):** QEMU builds are memory hungry, and running a VM plus possibly a second VM for testing will use RAM. We suggest **16 GB RAM minimum**. With 16 GB, you can allocate a couple gigabytes to your guest and use the rest for build processes and the host OS. If you can get 32 GB, that’s even better – it allows for larger guest memory (useful if testing DAX with large cache=always, which can map a lot of host memory) and more aggressive parallel compilation (each compiler job can use 1GB+ RAM easily for QEMU). Insufficient RAM can lead to swapping during compile or runtime, which will skew performance results.  

- **Storage:** Use an **SSD** for your development environment. Compiling QEMU involves thousands of small file reads/writes (source code, object files), where SSDs hugely outperform HDDs. An NVMe SSD is ideal, but any SATA SSD is fine. This will reduce build times (full build can go from 30+ minutes on an HDD to just a few minutes on an SSD with multi-core). It also helps your VMs – if your guest image is on the SSD, I/O benchmarks will measure more of virtiofs overhead rather than being limited by a slow disk. Ensure you have enough space (QEMU source + build can take ~GBs, each VM image can be several GB).  

- **Thermals:** When compiling or running benchmarks, your CPU will be under heavy load for extended periods. Good cooling is important to avoid thermal throttling. This is more of a laptop consideration – on a desktop it’s usually fine. If on a laptop, use a cooling pad and keep an eye on temperatures. Throttling could slow down your compile or make performance numbers inconsistent.  

- **Secondary Machine (Optional):** If you have access to a second machine or a server, you can use it to run long benchmarks or kernel builds in the guest, etc., while keeping your main dev machine free. This isn’t required, but some GSoC students use a separate test machine via SSH. At minimum, consider using **tmux** or **screen** sessions so you can run a VM or fio test in the background and continue coding.  

- **Networking:** Not critical for performance of this project, but ensure you have at least a Gigabit network if you plan to do any network filesystem tests or remote debugging. Virtio-fs mostly uses shared memory, so network isn’t in the picture there. But if you use ssh to log into the guest or transfer files, a reliable network helps.  

- **Kernel Version:** Use a newer Linux kernel on your host if possible. For fuse-over-io_uring, you need a kernel that supports it (Linux 6.14 or newer, as the io_uring FUSE patches are slated for 6.14 ([FUSE Hooks Up With IO_uring For Greater Performance Potential In ...](https://www.phoronix.com/news/Linux-6.14-FUSE#:~:text=,14%20stable))). Since Ubuntu 24.04 LTS might ship with an older kernel, consider installing a mainline kernel (from Ubuntu’s mainline PPA or compile 6.15+ yourself) for testing the io_uring functionality. This “hardware” aspect (kernel is sort of software, but fundamental) is important: without a supporting kernel, you can only develop half the feature. Developing against a moving target kernel might be tricky, but for testing, you’ll want to boot into 6.14+ when the time comes to actually see the effect of your changes.  

In summary, a **desktop or laptop with 4+ cores, 16+ GB RAM, and an SSD** will significantly enhance productivity. Many contributors use such setups for QEMU development. If your current PC is weaker, you can still proceed (QEMU can be built on dual-core/8GB, for example) but expect longer turnaround times for builds and possibly limited benchmarking fidelity. Investing in a bit more hardware muscle, if feasible, will pay off in time saved during the project.

## Project Focus: Early Deliverables, Prioritization, and Communication  
Finally, let’s outline how to tackle the project itself within 2 months, emphasizing early wins. In GSoC, it’s crucial to make steady, visible progress to build credibility with mentors and the community. Here’s how you can focus on the first 1–2 deliverables and communicate effectively:

- **Break the Project into Milestones:** Divide the “FUSE over io_uring” implementation into smaller tasks that each produce a tangible result. For example, an initial milestone could be *supporting basic read/write requests via io_uring* in virtiofsd. A second milestone could expand support to other FUSE operations (mkdir, unlink, etc.) or optimize buffer handling. By defining these sub-goals, you can work in iterations. Aim to complete a basic working prototype by the end of the first month (mid GSoC) – e.g., *virtiofsd can handle file reads using io_uring and it passes simple tests*. This gives you something to show at the mid-term evaluation.  

- **Prioritize Core Functionality:** Focus on the most impactful parts of the feature first. In this case, **file read and write operations** are the critical path for performance, so implement and test those with io_uring early. Metadata operations (like chmod, chown, etc.) are less performance-sensitive, so they could initially continue using the old path if needed. By getting reads/writes on io_uring, you’ll already solve the biggest bottleneck. Ensure this core works end-to-end: submit a read request via io_uring, get completion, send data to guest. Prove that this round-trip works reliably before adding more complexity.  

- **Incremental Testing & Validation:** After implementing the core io_uring logic for FUSE requests, test it thoroughly with simple scenarios. For instance, modify virtiofsd to use io_uring for reads, and try reading a file from the guest. Compare the result byte-for-byte with the original to ensure correctness. Once confident, switch writes to io_uring, test creating a file, etc. It’s fine if in early stages you handle only a subset of operations with io_uring and fall back to the default for others – just clearly mark TODOs for what’s next. Each incremental improvement should pass all existing tests (regression avoidance) and ideally come with a new simple test you devise for that case.  

- **Performance Checkpoints:** After each deliverable, run a quick benchmark to see if it moves the needle. This not only validates the approach but is motivating. For example, once reads/writes are using io_uring, run the fio read test – you might already see lower CPU usage or higher throughput. Even a 10% improvement is a good sign and something you can report. Conversely, if you see no improvement, that’s a signal to investigate or adjust course early (maybe the implementation isn’t as asynchronous as expected). Catching such issues early is only possible if you measure early.  

- **Communication of Progress:** Make your work visible. This can be through **weekly blog posts** or updates to your mentor. In these updates, highlight what you achieved (e.g., “implemented asynchronous read using io_uring, passing basic tests, saw ~5% throughput improvement in initial benchmark”), what issues you ran into, and what’s next. Early in the project, also share your understanding or design thoughts – for instance, write a brief summary of how you plan to integrate io_uring into the virtiofsd event loop. This helps mentors/course correct if needed.  

- **Engage with the Community Early:** Once you have a minimal viable change (maybe just a draft patch that adds the io_uring setup and one code path), consider sending an **RFC patch series** to the QEMU mailing list or virtio-fs mailing list. Mark it as “[RFC] virtiofsd: initial support for fuse-over-io_uring” and explain that it’s a work in progress. Include your early performance numbers if available. The goal is to get feedback or at least put it on maintainers’ radar. Even if the code isn’t ready to merge, the discussion can provide valuable pointers (perhaps someone already tried a similar approach, or a maintainer like Miklos Szeredi might give tips on the kernel side). Be sure to follow contributor guidelines when sending patches (checkpatch clean, proper subject prefixes, etc.). By demonstrating this proactiveness, you build credibility as someone serious about upstreaming their work.  

- **Document as You Go:** Keep notes on design decisions and how you addressed challenges. For instance, document how you handle completion ordering or concurrency with io_uring. This will make writing your final GSoC report and the commit messages easier. It also means if you need to hand off the project or collaborate, others can follow your thought process. Consider maintaining a markdown document in your repo for this purpose.  

- **Focus on Code Quality for Early Deliverables:** It’s tempting to rush prototypes (which is fine initially), but when you aim to get something merged or reviewed, polish it. Clean up debug prints, add comments where the logic is not obvious (e.g., “Using IORING_OP_URING_CMD here to submit fuse request to kernel ([fuse: fuse-over-io-uring [LWN.net]](https://lwn.net/Articles/997400/#:~:text=This%20adds%20support%20for%20uring,are%20still%20to%20be%20expected))”). If you introduce any new build dependency or kernel header usage, note that. Early deliverables that are well-written will make reviewers more comfortable and likely to support your continued work. Conversely, if the first thing they see is very messy, they might be wary. So, for the first 1–2 deliverables especially, put effort into code clarity and correctness (even if performance isn’t fully optimized yet).  

- **Time Management:** Two months can fly by. Try to have the first deliverable (even if small) done by the end of Week 4. This could simply be: “QEMU/virtiofsd builds with an io_uring backend (behind an option), and doesn’t break normal operation.” Even if performance gains aren’t realized yet, having a toggle or prototype implementation is a tangible outcome. From Week 5 onward, you can optimize and add features. Reserving the last week or two for bug fixes, writing documentation, and upstream preparation is wise. Thus, front-load the critical coding in weeks 3–6 if possible.  

- **Maintain Focus:** It’s easy to get sidetracked by interesting but non-critical aspects (e.g., experimenting with a different kernel bypass approach). Use your defined milestones to stay on track. If you find something truly blocking or a better approach mid-way, discuss it with your mentor quickly and adjust the plan rather than spinning wheels too long. Keeping the core goals in sight (reduce context switches, improve throughput for virtio-fs) will guide decision-making.  

- **Clear Communication of Results:** When you achieve a milestone, communicate it clearly: for instance, in your weekly update or blog, include a short section like “**Milestone Achieved**: Asynchronous READ/WRITE with io_uring is implemented. In a test with 1 thread reading a 1GB file, CPU usage dropped from 50% to 35% on the host, and throughput improved by 15%. Next, I will tackle multiple concurrent I/O and ensure flush/fsync are handled.” Such concise reporting shows progress and gives others confidence in your work. It’s also great material for your GSoC evaluations.  

By concentrating on a few key deliverables early (getting something working, even if not feature-complete, and demonstrating improvement), you establish momentum. This not only builds your credibility with the mentor and community but also boosts your own confidence. Each early success will make the subsequent challenges easier to handle. Remember that open-source development is as much about collaboration and communication as coding – so keep the conversation going with mentors and the QEMU community. By the end of the 2-month preparation (and certainly by the end of GSoC), you’ll want to have upstream-worthy patches. Planning, prioritizing, and iterating as outlined above will put you on the right path to achieve that.


