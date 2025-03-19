Got it! I will compile a comprehensive review of over 50 anti-sandbox and anti-virtual machine techniques, focusing on both emerging and well-known methods. The report will be structured into categories such as CPU-based, memory-based, API monitoring, and more. Each technique will include detailed implementation in C/C++ for Windows whenever possible, along with practical mitigation strategies for both security researchers and developers.

I'll notify you once the research is complete.

# Anti-Sandbox and Anti-Virtual Machine Evasion Techniques

Malware authors employ **anti-sandbox** and **anti-virtual machine (anti-VM)** techniques to detect when their code is running in a controlled analysis environment. Below is a comprehensive review of **50+ techniques**, organized by category (CPU-based, memory-based, API monitoring/hooks, timing-based, environment/configuration, and user-interaction checks). Each technique is explained in detail with Windows C/C++ code snippets where possible, and practical mitigation strategies for analysts and sandbox developers are discussed.

## CPU-Based Detection Techniques

CPU-level techniques leverage differences in how hardware or low-level instructions behave under virtualization. Many are hard to detect externally because they execute normal instructions that VMs may handle differently than physical machines.

### CPUID Hypervisor Flag Check (Hypervisor Bit)

**How it works:** The x86 `CPUID` instruction can reveal the presence of a hypervisor. When called with `EAX=1`, bit 31 of `ECX` is the **Hypervisor Present** flag. On a physical machine this bit is `0`, but on a virtual machine it is set to `1` ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=identify%20virtual%20environments%3A%20%E2%80%A2CPUID%3A%20This,it%20will%20equal%20to%201)). Malware uses this to decide if it’s in a VM. This method is popular because it’s a straightforward, single-instruction check that doesn’t require privileged access.

**Code (CPUID hypervisor flag):** The following example uses inline assembly to execute CPUID and test the 31st bit of ECX. It sets a boolean if a VM is detected (bit = 1) ([Defeating malware's Anti-VM techniques (CPUID-Based Instructions) | Rayanfam Blog](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/#:~:text=int%20main%28%29%20,UnderVM)) ([Defeating malware's Anti-VM techniques (CPUID-Based Instructions) | Rayanfam Blog](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/#:~:text=The%20above%20code%20set%20eax%3D1,finally%20saved%20on%20%E2%80%9CIsUnderVM%E2%80%9D%20variable)):

```cpp
#include <iostream>
int main() {
    bool inVirtualMachine = false;
    __asm {
        xor    eax, eax      // set EAX = 0
        inc    eax           // now EAX = 1
        cpuid               // perform CPUID with EAX=1
        bt     ecx, 0x1F    // bit test ECX bit 31 (0x1F hex)
        jc     is_vm        // jump if carry (bit was 1)
        jmp    done
      is_vm:
        mov    inVirtualMachine, 1
      done:
    }
    std::cout << (inVirtualMachine ? "VM detected" : "No VM detected");
    return 0;
}
```

If running inside a hypervisor, this program will print "VM detected", otherwise "No VM detected". The key is the `bt ecx, 0x1F` which checks the hypervisor bit and sets the flag accordingly ([Defeating malware's Anti-VM techniques (CPUID-Based Instructions) | Rayanfam Blog](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/#:~:text=int%20main%28%29%20,UnderVM)) ([Defeating malware's Anti-VM techniques (CPUID-Based Instructions) | Rayanfam Blog](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/#:~:text=The%20above%20code%20set%20eax%3D1,finally%20saved%20on%20%E2%80%9CIsUnderVM%E2%80%9D%20variable)).

**Mitigation:** To defeat this check, **sandbox developers** can intercept or modify the CPUID result. Many hypervisors allow masking of the hypervisor bit or use a **“stealth mode”** where they report it as zero. For example, custom VM configurations can hide the hypervisor presence. **Analysts** running malware can use such hypervisor settings or run the sample on bare-metal if possible. Another approach is using hardware virtualization extensions that allow transparency – e.g., running the analysis *outside* the guest OS (so the malware sees no hypervisor in CPUID). The goal is to ensure the CPUID flag appears as it would on a real machine.

### CPUID Virtualization Vendor ID

**How it works:** Another CPUID trick is querying the **virtualization vendor ID string**. Using `CPUID` with `EAX=0x40000000` returns a hypervisor-defined vendor signature in registers EBX, ECX, EDX ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=Anti,%E2%80%9CMicrosoft%20HV%E2%80%9D%20%E2%97%A6VMware%20%3A%20%E2%80%9CVMwareVMware%E2%80%9D)). Known values include `"VMwareVMware"` for VMware, `"Microsoft Hv"` for Hyper-V, `"XenVMMXenVMM"` for Xen, `"VBoxVBoxVBox"` for VirtualBox, etc. ([Defeating malware's Anti-VM techniques (CPUID-Based Instructions) | Rayanfam Blog](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/#:~:text=%3E%20%20%20,VMware%20%3A%20%E2%80%9CVMwareVMware%E2%80%9D)) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,Private%20as%20license%20value)). Malware checks these returned strings to identify the specific VM platform.

**Code (CPUID vendor string):** This snippet calls CPUID with EAX=0x40000000 and checks for the "VMware" signature in ECX/EDX ([Defeating malware's Anti-VM techniques (CPUID-Based Instructions) | Rayanfam Blog](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/#:~:text=__asm%20,NopInstr%20mov%20IsUnderVM%2C%200x1%20NopInstr)) ([Defeating malware's Anti-VM techniques (CPUID-Based Instructions) | Rayanfam Blog](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/#:~:text=The%20above%20code%20set%20eax%3D0x40000000,will%20finally%20save%20into%20%E2%80%9CIsUnderVM%E2%80%9D)):

```cpp
#include <iostream>
#include <intrin.h>  // for __cpuid on MSVC
int main() {
    int info[4];
    __cpuid(info, 0x40000000);
    // The vendor string is 12 bytes stored in EBX, ECX, EDX of CPUID output
    unsigned int part1 = info[1]; // EBX
    unsigned int part2 = info[2]; // ECX
    unsigned int part3 = info[3]; // EDX
    // "VMwareVMware" split into 3 parts in little-endian form:
    if (part2 == 0x4D566572 && part3 == 0x65726177) {  // hex for "MVre" and "eraw"
        std::cout << "VMware hypervisor detected\n";
    } else {
        std::cout << "No known hypervisor vendor detected\n";
    }
}
```

In this code, we use the compiler intrinsic `__cpuid` for clarity. The check compares the result with known hex values corresponding to "VMware" (the code above checks for VMware’s signature specifically) ([Defeating malware's Anti-VM techniques (CPUID-Based Instructions) | Rayanfam Blog](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/#:~:text=__asm%20,NopInstr%20mov%20IsUnderVM%2C%200x1%20NopInstr)). Similar comparisons could be made for other vendor strings.

**Mitigation:** **Sandbox developers** can randomize or remove identifying vendor strings. For instance, VMware has an option to customize the exposed CPUID vendor, and VirtualBox can be configured to use a generic string. Another tactic is to intercept this CPUID call at the hypervisor level and return a fake **vendor-neutral** string or zeros. **Analysts** should be aware of this check; if possible, they can patch the malware binary to bypass string comparisons or use a hypervisor that already neutralizes the vendor ID. Some modern sandboxes choose hypervisors with minimal fingerprint (e.g., KVM with no custom vendor string) to mitigate this detection.

### Interrupt Descriptor Table Register Check (Red Pill via SIDT)

**How it works:** The **“Red Pill”** technique uses the `SIDT` instruction to detect VMs by examining the location of the Interrupt Descriptor Table (IDT) in memory ([SIDT, Red Pill - Unprotect Project](https://unprotect.it/technique/sidt-red-pill/#:~:text=Red%20Pill%20is%20a%20technique,it%20in%20a%20memory%20location)). In a normal OS, the IDT is stored at a typical address (often lower in memory), but virtualization often relocates it to avoid conflicts with the host. For example, on VMware the IDT base often lies around `0xFFXXXXXX`, and on Microsoft VirtualPC around `0xE8XXXXXX`, whereas on a physical Windows machine it’s typically near `0x80FFFFFF` ([Microsoft PowerPoint - SANSFire2006.ppt](https://handlers.sans.org/tliston/ThwartingVMDetection_Liston_Skoudis.pdf#:~:text=%E2%80%93%20On%20VMware%20guest%20machines%2C,are%20in%20a%20real%20machine)). The original Red Pill check simply obtains the IDT base and looks at its most significant byte; if it’s above a certain threshold (e.g., > `0xD0` in the first byte, meaning an address above 0xD0000000), then it assumes a virtual environment ([Microsoft PowerPoint - SANSFire2006.ppt](https://handlers.sans.org/tliston/ThwartingVMDetection_Liston_Skoudis.pdf#:~:text=SIDT%20%E2%80%93%20If%20it%E2%80%99s%20greater,message%20saying%20that%20it%20is)).

**Code (SIDT Red Pill):** The following code retrieves the IDTR base address via `SIDT` and checks if it falls into a high memory range indicative of a VM:

```cpp
#include <stdio.h>
#include <stdint.h>

int main() {
    unsigned char idtr[6];  // IDTR structure: 6 bytes on x86 (limit:2 bytes, base:4 bytes)
    __asm sidt idtr;
    uint32_t idtBase = *(uint32_t*)(idtr + 2);  // extract base address
    printf("IDT Base: 0x%X\n", idtBase);
    // Red Pill check: if IDT base > 0xD0000000 -> likely VM
    if (idtBase > 0xD0000000) {
        printf("Virtual machine suspected (Red Pill trigger)\n");
    } else {
        printf("Running on a physical machine (no Red Pill trigger)\n");
    }
    return 0;
}
```

This prints the IDT base and uses the classic threshold (0xD0000000) as the indicator ([Microsoft PowerPoint - SANSFire2006.ppt](https://handlers.sans.org/tliston/ThwartingVMDetection_Liston_Skoudis.pdf#:~:text=SIDT%20%E2%80%93%20If%20it%E2%80%99s%20greater,message%20saying%20that%20it%20is)). On VMware/VirtualBox the output address is usually high (triggering the message), whereas on real hardware it’s lower.

**Mitigation:** Because `SIDT` is not a privileged instruction, **hypervisors cannot easily intercept it** ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=of%20the%20malware%20in%20a,VM%20instead%20of%20on%20bare)). Instead, mitigation involves shaping the environment: modern hypervisors try to place the guest IDT at an address that looks “normal.” For instance, some VM platforms now map certain structures in low memory or use hardware features to avoid the telltale high address. **Sandbox developers** should ensure their VM’s IDT (and similar descriptors like the GDT/LDT) reside at typical physical machine addresses if possible. Alternatively, they can run analysis on bare-metal or use hardware-assisted virtualization that doesn’t rely on relocating the IDT. **Researchers** who encounter Red Pill can run the sample on a real machine or in a cloud VM that is less fingerprintable. Another mitigation is to modify the check (e.g., patch the malware to skip the SIDT comparison when analyzing it), though this requires reverse-engineering effort.

### Descriptor Table and Control Register Checks (GDT, LDT, SMSW)

**How it works:** Variants of the Red Pill use similar instruction tests. The `SGDT` (Store Global Descriptor Table) and `SLDT` (Store Local Descriptor Table) instructions, and reading certain control registers or status flags (like via `SMSW` – Store Machine Status Word) can also yield different values in a VM vs. physical machine ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=Instruction%20Testing%20,related%20to%20Unprotect%20technique%20U1325)). Like SIDT, these instructions return data that the hypervisor may relocate or modify. For example, the Global Descriptor Table register base might be placed at a distinctive address under a VMM. `STR` (Store Task Register) is another instruction used (sometimes called the "No Pill" technique) to detect VMs by getting the Task State Segment selector – some hypervisors don’t emulate this exactly as on real hardware ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=metal,used%20to%20detect%20the%20execution)).

**Code (GDT check via SGDT):** 

```cpp
#include <stdio.h>
#include <stdint.h>
int main() {
    unsigned char gdtr[6];
    __asm sgdt gdtr;
    uint32_t gdtBase = *(uint32_t*)(gdtr + 2);
    printf("GDT Base: 0x%X\n", gdtBase);
    // Simple heuristic: extremely high GDT base could indicate VM
    if (gdtBase > 0xD0000000) {
        printf("High GDT base - likely running in VM\n");
    }
    return 0;
}
```

This code is analogous to the IDT check but for the GDT base. Similarly, one could use `sldt` or `str` in inline assembly to retrieve LDT or Task Register values. Each of these have known typical ranges; if the value falls into a suspicious range or pattern (for instance, a specific selector value from `STR` known to be used by VMware), the malware can flag a VM ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=metal,used%20to%20detect%20the%20execution)).

**Mitigation:** These low-level checks are tricky. **Sandbox developers** should study which values their hypervisor gives for GDT/LDT/Task Register and try to align them with what a normal system would have. Some modern sandboxes instrument these instructions at the hypervisor level if possible (e.g., using VT-x trapping of certain privileged operations in kernel-mode malware, though from user-mode they might not trap). In practice, ensuring the **descriptor tables** and **status registers** don’t have out-of-place values is key – perhaps by using newer virtualization tech or patches that specifically address these known tells. **For analysts**, the advice is similar to SIDT: use VMs known to be resistant to these checks (some research sandbox hypervisors have custom mitigations), or analyze on actual hardware when such checks are suspected.

### Trap Flag-Based Detection (Single-Step Exception)

**How it works:** A more **recent technique** abuses the CPU’s **Trap Flag (TF)** to differentiate VM vs. real hardware. The Trap Flag in the EFLAGS register causes a debug exception after each instruction (single-step mode). Mark Lim (Unit 42) discovered that many hypervisors historically did not perfectly emulate this behavior ([Evade Sandboxes With a Single Bit – the Trap Flag](https://unit42.paloaltonetworks.com/single-bit-trap-flag-intel-cpu/#:~:text=Unit%2042%20has%20discovered%20a,CPU%20after%20setting%20this%20single)). Malware can set the TF and then execute an instruction to see if a single-step exception occurs as expected. If the behavior deviates (e.g., no exception or an abnormal pattern of exceptions), it indicates a virtualized environment ([Evade Sandboxes With a Single Bit – the Trap Flag](https://unit42.paloaltonetworks.com/single-bit-trap-flag-intel-cpu/#:~:text=match%20at%20L104%20The%20trap,allow%20the%20contents%20of%20the)). In one case, a trojan (Lampion) used this to generically evade sandboxes ([Evade Sandboxes With a Single Bit – the Trap Flag](https://unit42.paloaltonetworks.com/single-bit-trap-flag-intel-cpu/#:~:text=Unit%2042%20has%20discovered%20a,CPU%20after%20setting%20this%20single)).

**Code (Trap Flag detection):** Enabling the trap flag in user-mode and catching the exception can be done with structured exception handling. Below is a conceptual example (note: proper SEH setup is needed for a real implementation):

```cpp
#include <windows.h>
#include <iostream>

int main() {
    __try {
        __asm {
            pushfd                   // push original EFLAGS
            or dword ptr [esp], 0x100  // set TF (bit 8) on the copy
            popfd                    // pop modified EFLAGS (TF now set)
            nop                      // execute one instruction
        }
        // If running on real hardware, the single-step exception will jump to __except.
        std::cout << "No VM detected (single-step occurred)\n";
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // If we end up here, it means an exception was caught:
        // On a real machine, this should catch the single-step.
        // If this __except is *not* hit, something is off (likely a VM not generating the expected exception).
        std::cout << "VM detected or abnormal Trap Flag behavior\n";
    }
    return 0;
}
```

In this snippet, we set the trap flag and execute a `nop`. On a normal system, a single-step (`EXCEPTION_SINGLE_STEP`) should be raised and handled by the `__except` block. If running in a VM that mis-handles TF, the behavior might differ (e.g., no exception, or continuing execution unexpectedly). The malware can detect that difference by where the flow ends up.

**Mitigation:** The proper emulation of CPU flags is essential. **Sandbox developers** should ensure their hypervisor correctly handles the Trap Flag at the CPU level ([Navigating the Vast Ocean of Sandbox Evasions](https://unit42.paloaltonetworks.com/sandbox-evasion-memory-detection/#:~:text=fact%20that%20many%20hypervisors%20incorrectly,behavior%20of%20the%20trap%20flag)). In fact, once this technique was publicized, vendors patched their hypervisors to fix the TF emulation bug ([Evade Sandboxes With a Single Bit – the Trap Flag](https://unit42.paloaltonetworks.com/single-bit-trap-flag-intel-cpu/#:~:text=the%20incorrect%20emulation%20of%20the,malware%20sample%20using%20this%20technique)). For a sandbox, updating to a version where such CPU bugs are resolved is crucial. If not possible, another mitigation is to run the code under a *hypervisor that uses hardware breakpoints outside the guest* (so the guest cannot discern the difference). **For researchers**, if they suspect Trap Flag checks, they can attempt to disable that code path (by patching the malware binary) or use an environment known to handle TF properly (for example, some cloud VMs or newer virtualization platforms might not exhibit the issue). Ultimately, the best solution is for the sandbox to **faithfully emulate CPU behavior**, leaving no easy single-bit indicators for malware.

### VMware I/O Port Communication ("Backdoor" `IN` Instruction)

**How it works:** VMware hypervisors provide a special I/O port interface (often called the VMware backdoor) that allows the guest to communicate with the host (for things like clipboard sharing, etc.). This is accessible via specific I/O port instructions. Malware can attempt to use this interface – if it succeeds (i.e., doesn’t crash and returns expected data), it means VMware is present ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=Anti,Otherwise%20it%20will%20fail)). Typically, the malware will execute an `IN` instruction on port **0x5658** with certain registers preset (a magic value). On VMware, the hypervisor will respond with a signature. On a non-VM system, executing an I/O port read from ring3 either raises an exception (privileged instruction) or returns nothing meaningful ([Anti-VM: in instruction (VMWare) · Issue #228 · ayoubfaouzi/al-khaser · GitHub](https://github.com/LordNoteworthy/al-khaser/issues/228#:~:text=Can%20you%20please%20try%20this,see%20it%20confirmed%20before%20including)).

**Code (VMware backdoor detection):** The code below tries the VMware port `0x5658`. It uses inline assembly within a structured exception handler to catch the privilege exception if not in a VM ([Anti-VM: in instruction (VMWare) · Issue #228 · ayoubfaouzi/al-khaser · GitHub](https://github.com/LordNoteworthy/al-khaser/issues/228#:~:text=mov%20%20%20%20eax%2C,%2F%2F%20port%20number)) ([Anti-VM: in instruction (VMWare) · Issue #228 · ayoubfaouzi/al-khaser · GitHub](https://github.com/LordNoteworthy/al-khaser/issues/228#:~:text=in%20%20%20%20,%2F%2F%20set%20return%20value)):

```cpp
#include <windows.h>
#include <iostream>

bool IsRunningOnVMware() {
    bool isVMware = false;
    __try {
        __asm {
            push   ebx
            push   ecx
            push   edx
            mov    eax, 'VMXh'   // magic value
            mov    ebx, 0        // arbitrary value, will be overwritten if in VM
            mov    ecx, 0x0A     // command: get VMware version
            mov    edx, 'VX'     // port number 0x5658 ('VX' in little-endian)
            in     eax, dx       // attempt to read from port 0x5658
            cmp    ebx, 'VMXh'   // VMware should echo magic value into EBX
            sete   al            // set AL=1 if EBX == 'VMXh'
            movzx  eax, al
            mov    isVMware, eax // isVMware = result (1 if VMXh magic seen)
            pop    edx
            pop    ecx
            pop    ebx
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        isVMware = false;
    }
    return isVMware;
}

int main() {
    if (IsRunningOnVMware()) {
        std::cout << "VMware detected\n";
    } else {
        std::cout << "No VMware detected\n";
    }
    return 0;
}
```

Inside the `__asm` block, we prepare registers and use `IN eax, dx` on port `0x5658`. On VMware, this will not raise an exception and will set EBX to `'VMXh'` (the magic constant) as a response ([Anti-VM: in instruction (VMWare) · Issue #228 · ayoubfaouzi/al-khaser · GitHub](https://github.com/LordNoteworthy/al-khaser/issues/228#:~:text=mov%20%20%20%20eax%2C,%2F%2F%20port%20number)). The code then checks EBX. If it matches, we conclude we’re on VMware. If the instruction causes an exception (caught by `__except`), we assume we are *not* on VMware or not in ring0. This technique only specifically detects VMware, but malware often includes similar checks for other platforms (for example, reading MSRs or I/O ports known to be used by VirtualBox, etc.).

**Mitigation:** **Sandbox/VM developers** can disable or hide these special I/O port communications. VMware, for instance, allows disabling its backdoor interface (setting `monitor_control.disable_directexec = "TRUE"` or related config to prevent guest from using it). Another approach is to run the sandbox on a hypervisor that doesn’t use such backdoor ports or has them well-protected. In general, preventing *unprivileged I/O port access* is ideal – normally ring3 code shouldn’t execute `in`/`out` instructions, but VMware’s backdoor is a special case where the hypervisor intercepts it. Sandbox developers should either intercept those attempts and emulate a failure (so malware doesn’t get the expected reply) or ensure an exception is thrown just like on a real machine. **For analysts**, if using VMware, be aware of this detection: consider using a different hypervisor or enabling settings to hide the backdoor. Some researchers intentionally run malware in VirtualBox or KVM when they know it specifically targets VMware, or vice-versa, to evade the malware’s evasion!

### Non-Emulated Instructions and MSR Access

**How it works:** Malware may try to execute instructions that are not commonly used and see if they behave unusually. For example, certain older virtualization platforms did not support the full range of SSE/MMX instructions or specific newer CPU instructions. One example cited is malware checking for **MMX support** – historically, if a VM didn’t implement MMX, the absence would indicate a VM ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=Anti,For%20example)). Additionally, reading **Model-Specific Registers (MSRs)** that are normally present on real CPUs but might be absent or trigger errors on VMs is another trick. For instance, malware might attempt to read an MSR that should exist on a bare-metal CPU; if running under a hypervisor, this could cause a VM exit or exception if not handled. Similarly, executing privileged instructions (like `CLI` to disable interrupts or `SGX` instructions) in user-mode and seeing if/how they fail can differentiate environments.

*Note:* These techniques are less common in typical malware because they may crash the process if not carefully handled (unlike CPUID which is safe). However, advanced malware might wrap such instructions in exception handlers to safely probe the environment.

**Code (MSR read example):** The following tries to read an arbitrary MSR (0x174 is IA32_SYSENTER_EIP for example) and uses `__readmsr` intrinsic (requires driver or privileged context normally). We illustrate conceptually:

```cpp
#include <intrin.h>
#include <iostream>
#include <stdexcept>

int main() {
    try {
        unsigned __int64 val = __readmsr(0x174); // attempt read MSR 0x174
        std::cout << "MSR[0x174] = " << std::hex << val << "\n";
    } catch (...) {
        std::cerr << "MSR read failed (possibly in VM or no permission)\n";
    }
}
```

In user-mode, this will likely throw an exception (since reading MSR is privileged). Malware might do this in kernel mode (via a driver) or use a different approach (e.g., `asm volatile("rdmsr")` with exception handling). If running in a VM without proper handling, the exception might indicate a hypervisor is present (or simply that it’s user-mode – so this method is more applicable in kernel-mode malware).

**Mitigation:** **Sandbox developers** should ensure that common instruction sets are enabled in the VM (modern hypervisors generally support MMX/SSE, so that specific check is mostly historical). For MSRs and odd instructions, the sandbox can intercept and handle them gracefully. For example, if malware attempts a known problematic instruction, the hypervisor could emulate a realistic response. Patching hypervisors to handle corner-case instructions (or configuring them to expose features like a real CPU) helps. In practice, these checks are less straightforward for malware (due to risk of crashing), so they are not as prevalent. **Analysts** typically won’t need to do much here except use up-to-date VM platforms. If analyzing very sophisticated malware that includes a driver to do MSR checks, one might need to use a fully emulated environment or instrumentation that can catch the attempt. Overall, staying current with VM technology mitigates many of these quirks.

## Memory-Based Detection Techniques

Memory-based techniques involve examining memory layout, system memory properties, or scanning for known signatures that betray virtualization. These don’t rely on special CPU instructions, but on differences in how memory is allocated or labeled in VMs.

### Physical Memory Size and Configuration Checks

**How it works:** Sandboxes and VMs often run with minimal resources compared to modern real machines. Malware frequently queries the system’s memory size and configuration to see if it’s unusually small or aligned to powers of two (common in VMs). For example, if total physical RAM is 1GB or 2GB, it might be a tell (many user machines today have >4GB). Malware can call Windows APIs like `GlobalMemoryStatusEx` to get total RAM ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,todo)) ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=Unprotect%20technique%20U1340,related%20to%20Unprotect%20technique%20U1313)). Similarly, it might check if there’s a page file or how large it is – some sandboxes disable or have small page files.

**Code (Memory size check):** 

```cpp
#include <windows.h>
#include <iostream>

int main() {
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    DWORDLONG totalPhys = mem.ullTotalPhys;
    std::cout << "Total RAM: " << (totalPhys / (1024*1024)) << " MB\n";
    // Flag if RAM is below a threshold (e.g., 2048 MB)
    if (totalPhys < 2048ULL*1024*1024) {
        std::cout << "Suspicious: Low memory (possible VM)\n";
    }
}
```

This prints total RAM and flags if under 2GB. Modern PCs typically have much more, so malware might use 4GB as a threshold (as an example, one source noted “Most modern machines have at least 4 GB of memory” ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=Unprotect%20technique%20U1340,related%20to%20Unprotect%20technique%20U1313))).

**Mitigation:** **Researchers/analysts** can configure their VMs with higher RAM to evade simple checks (e.g., give the VM 8GB if possible to appear normal). **Sandbox providers** often configure analysis VMs to have realistic hardware specs – e.g., 4GB+ RAM, to avoid tripping this heuristic ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=Unprotect%20technique%20U1340,related%20to%20Unprotect%20technique%20U1313)). Another mitigation is to intercept calls like `GlobalMemoryStatusEx` and return a fake inflated value (though that can be risky if the malware tries to actually allocate memory based on that value). Usually, simply allocating more resources to the VM is easiest. Note that some malware also check for *excessively* high RAM (since a sandbox might also misconfigure and give an exact round number like 8GB with nothing else on disk, which could still look suspicious if other indicators pile up). Aim for plausibility: memory size consistent with the OS and other specs (e.g., 8GB for a Windows 10 machine is plausible).

### Memory Layout Artifacts (Scanning for Hypervisor Signatures in Memory)

**How it works:** Certain hypervisors leave telltale data in memory. Malware can scan the raw memory for specific strings like "VMware" or "VirtualBox" that might appear in firmware tables or driver memory ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=Check%20Memory%20Artifacts%20B0009,Windows%20registry%20or%20other%20places)). For instance, VMware’s hypervisor or tools may have the string "VMware" present in memory. Another example: VirtualBox’s BIOS has a default BIOS date (often **06/23/99**), which malware can retrieve via `GetSystemFirmwareTable` or by reading the registry (e.g., `HARDWARE\Description\System\SystemBiosDate`) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,Logical%20Unit%20Id)). If it matches the known VM BIOS date, that’s a giveaway. Similarly, certain memory locations such as the video BIOS might contain "VBOX" or "VirtualBox" strings ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,VMWARE)).

Malware might allocate memory and then use device drivers or system calls to read physical memory looking for these patterns. This is less common in user-mode (requires privilege or driver) but is a known technique.

**Code (Firmware table check):** 

```cpp
#include <windows.h>
#include <iostream>
#include <vector>

int main() {
    // Get RAW SMBIOS firmware table
    DWORD size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    std::vector<byte> buffer(size);
    GetSystemFirmwareTable('RSMB', 0, buffer.data(), size);
    // Search for "VirtualBox" in the BIOS SMBIOS data
    std::string biosData(buffer.begin(), buffer.end());
    if (biosData.find("VirtualBox") != std::string::npos) {
        std::cout << "VirtualBox signature found in firmware table (VM detected)\n";
    }
}
```

This code retrieves the raw SMBIOS table and searches for the substring "VirtualBox". Many virtualization platforms include identifying strings in SMBIOS or ACPI tables (like OEM IDs). Malware can similarly query ACPI tables for "VBOX" OEM ID ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=)). If such a substring is found, it’s almost certainly a VM.

**Mitigation:** **Sandbox developers** should scrub identifying strings from BIOS/firmware if possible. Some hypervisors allow customization of BIOS information (e.g., change the BIOS date, manufacturer to something generic). Ensuring that strings like "VirtualBox", "VMware", "QEMU" are removed or replaced in firmware tables is important. Another approach is to use **custom BIOS/ACPI data** that mimics a real vendor (for instance, set the BIOS vendor to "Dell Inc." and use a realistic BIOS date). **Analysts** using public sandboxes can’t change this, but if setting up their own VM, they can use tools or scripts to patch these values (there are community tools for VirtualBox/VMware to set custom DMI strings). If malware is scanning memory broadly for certain strings, that’s harder to mitigate without controlling the hypervisor – in such cases, running on a platform it doesn’t expect can help (e.g., some malware only looks for "VirtualBox" and "VMware"; using a less common hypervisor might evade that specific scan).

### Unusual Memory Mappings and Interrupt Tables

**How it works:** Beyond just IDT (covered in CPU section), malware might look at memory-mapped structures like the **Local Descriptor Table (LDT)** or **Interrupt Descriptor Table** base address directly from memory. On Windows, the IDT is stored in the kernel’s memory space. Malware with the right privileges might examine those addresses. Another trick is checking the **Interrupt Vector Table** on older systems or the **presence of certain emulator memory patterns** (some older emulators put magic values at known addresses). Modern malware less frequently uses direct memory peeking due to requiring kernel access or complex code, but it’s part of the arsenal.

**Example:** One known memory artifact is the location of the **IDT, GDT, LDT** themselves as stored in memory (not just via SIDT instruction). For instance, the values returned by SIDT are actually stored at specific global variables in the OS; however, leveraging that requires debug symbols or specific offsets, which is not generic enough for most malware. Instead, they rely on the instructions approach described earlier.

Another example: checking if certain **memory ranges are present or absent**. Some sandbox environments might have a different physical memory map. Malware could use the `NtQuerySystemInformation` with `SystemPhysicalMemoryInformation` (if available) to see how memory is laid out. If it finds only one contiguous block of physical memory of exactly the VM’s size, that could hint at a VM (whereas a real system might have holes or reserved areas).

**Mitigation:** The mitigations overlap with earlier ones – ensure the memory layout looks typical. **Sandbox devs** should avoid obvious anomalies like an unsurprising contiguous block from 0x0 to X with no holes. Many of these are edge cases, and there’s not much evidence of widespread malware scanning raw memory maps in user mode (because it’s complicated and often requires privileges). Still, staying aware of such possibilities is useful. **Analysts** generally won’t have to act on this unless analyzing malware known for using drivers to inspect memory, in which case using a controlled kernel debugging or a hypervisor that can intercept such reads is advisable.

## API Monitoring & Hook Detection Techniques

Dynamic analysis sandboxes and AV products often inject hooks into API functions to log behavior. Malware can detect these hooks or the presence of analysis-specific DLLs to know it’s being watched. These techniques are *anti-sandbox* in the sense that many sandboxes rely on in-guest monitoring.

### API Function Hook Presence (Patched Prologues)

**How it works:** Sandboxes commonly hook Windows API calls (like `CreateFile`, `WriteFile`, etc.) to record what the malware does. Hooking often involves overwriting the first bytes of a function with a jump to monitoring code. Malware can detect this by inspecting the in-memory bytes of APIs. For example, on a clean system, the start of `CreateFileA` in kernel32.dll has a standard prologue; if it’s been hooked, it might begin with a JMP instruction to some other address (often in a monitoring DLL) ([Navigating the Vast Ocean of Sandbox Evasions](https://unit42.paloaltonetworks.com/sandbox-evasion-memory-detection/#:~:text=The%20first%20broad%20category%20of,see%20if%20they%20are%20hooked)). Attackers can read a few bytes of key APIs and look for unnatural JMPs or instructions that wouldn’t normally be there.

**Code (hook detection for CreateFileA):** 

```cpp
#include <windows.h>
#include <iostream>

bool IsFunctionHooked(const char* module, const char* funcName) {
    HMODULE hMod = GetModuleHandleA(module);
    if (!hMod) return false;
    void* funcAddr = GetProcAddress(hMod, funcName);
    if (!funcAddr) return false;
    // Read the first few bytes of the function
    unsigned char firstBytes[6];
    memcpy(firstBytes, funcAddr, 6);
    // Check if the first byte is a JMP (0xE9 or 0xE8 for call/jmp relative)
    return (firstBytes[0] == 0xE9 || firstBytes[0] == 0xE8);
}

int main(){
    if (IsFunctionHooked("kernel32.dll", "CreateFileA")) {
        std::cout << "CreateFileA is hooked (possible sandbox/monitor detected)\n";
    } else {
        std::cout << "CreateFileA is not hooked\n";
    }
}
```

This simplistic check looks for an `E9` or `E8` opcode at the start of `CreateFileA` (which would indicate a JMP/CALL). Real implementations might also check for a far jump (`0xFF` with certain modrm) or other signs of trampolines. Figure 1 of Unit 42’s report illustrates this concept – showing normal vs hooked API prologue ([Navigating the Vast Ocean of Sandbox Evasions](https://unit42.paloaltonetworks.com/sandbox-evasion-memory-detection/#:~:text=In%20Figure%201%2C%20we%20see,been%20instrumented%20in%20a%20sandbox)).

**Mitigation:** The best mitigation is **not to hook APIs in the malware’s own process**. **Sandbox developers** increasingly use external monitoring (e.g., monitoring from the hypervisor or using ETW event tracing) so that the in-process bytes remain untouched ([Navigating the Vast Ocean of Sandbox Evasions](https://unit42.paloaltonetworks.com/sandbox-evasion-memory-detection/#:~:text=The%20gold%20standard%20for%20preventing,byte%20anywhere%20in%20the%20OS)). If hooking is necessary, one strategy is to use stealthier hooks that are harder to detect (for instance, using hardware breakpoints or less conspicuous patching), but those can be complex. Some advanced sandboxes use a **hypervisor-based hooking** where the guest’s memory is not modified at all (they trap syscalls or use memory introspection) ([Navigating the Vast Ocean of Sandbox Evasions](https://unit42.paloaltonetworks.com/sandbox-evasion-memory-detection/#:~:text=Instead%20of%20instrumenting%20APIs%20by,as%20shown%20in%20Figure%203)). From the malware perspective, if it doesn’t see patched bytes, it can’t flag the hook. **Analysts** who roll their own instrumentation should be aware of this and possibly avoid inline hooks. In practice, using a product that emphasizes “transparent analysis” is key – for example, Intel PT or other side-band recording rather than code hooks. If you must use hooks (e.g., in a debugger), know that malware may detect them and try to evade; one could temporarily remove hooks before letting the malware run its checks, then restore them (some sandbox systems try such tricky timing maneuvers, though it’s not foolproof).

### Unhooking or Bypassing Instrumentation

**How it works:** Some malware not only detects hooks but actively **unhooks** them. For instance, GuLoader was observed restoring the original bytes of hooked functions like `ZwProtectVirtualMemory` to bypass monitoring ([Navigating the Vast Ocean of Sandbox Evasions](https://unit42.paloaltonetworks.com/sandbox-evasion-memory-detection/#:~:text=Figure%202%20shows%20an%20example,to%20restore%20the%20original%20functionality)). By reading the expected bytes from disk (from the DLL file on disk) and comparing to memory, malware can identify changes and patch them back. This is an offensive evasion: the malware neutralizes the sandbox’s hooks to operate freely.

This isn’t exactly a *detection* (malware might not quit but rather disable the hooks), but it’s related – it reveals the sandbox and evades it at the same time.

**Code concept:** Pseudo-code for unhooking might be:

```cpp
// Pseudo-code: compare in-memory function bytes to on-disk image, and restore if different.
void UnhookFunction(const char* dll, const char* funcName) {
    HMODULE hMod = GetModuleHandleA(dll);
    void* funcAddr = GetProcAddress(hMod, funcName);
    // Read original bytes from file
    // (Open dll file, find PE section for code, get offset of funcName's address, read bytes)
    // Here we assume we have originalBytes array from disk
    BYTE originalBytes[16];
    // ... (code to fill originalBytes omitted for brevity)
    if (memcmp(funcAddr, originalBytes, 16) != 0) {
        DWORD oldProtect;
        VirtualProtect(funcAddr, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(funcAddr, originalBytes, 16);
        VirtualProtect(funcAddr, 16, oldProtect, &oldProtect);
    }
}
```

This outlines how malware could restore the first 16 bytes of an API if altered. The actual implementation requires parsing the PE file to get the function’s offset, which is doable with Windows APIs or manually.

**Mitigation:** The mitigation here is similar – **avoid in-line hooks** that can be tampered with. If malware can correct the bytes, your sandbox loses visibility. Using out-of-process monitoring or hypervisor-level traps means there’s nothing in the process to unhook. Some endpoint solutions use a hypervisor or driver to intercept syscalls *after* the fact, making it invisible to the process. **Sandbox developers** should also monitor for unusual memory writes to API regions – if malware tries to patch kernel32.dll in memory, that itself is a red flag. They could allow it but note it (since that indicates evasion attempt) or prevent it with memory protection (though preventing it might reveal to the malware that something is fighting back). **Analysts** using debuggers should note if the malware tries to modify code – that might indicate it’s unhooking your breakpoints or instrumentation, which means you’ll need to step up your stealth (e.g., use a trace recorder rather than breakpoints).

### Detection of Analysis or Security DLLs

**How it works:** Instead of checking function bytes, malware can look for known DLLs loaded in its process that belong to analysis tools or AV. Many sandboxes inject helper DLLs or known libraries. For example, Sandboxie injects `SbieDll.dll`, certain AVs use `snxhk.dll` (Avast) or `avghookx.dll` (AVG) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,dir_watch.dll%20%28iDefense%20Labs)). Malware can enumerate loaded modules via `EnumProcessModules` or walk the PEB loader data and check module names. If it finds any of those known names, it can assume it’s under analysis or in a sandbox and then act accordingly (halt, mislead, etc.).

**Code (check for sandbox DLLs):**

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
int main() {
    const char* blacklist[] = {
        "sbiedll.dll",    // Sandboxie
        "api_log.dll",    // CWSandbox/iDefense
        "dir_watch.dll",  // CWSandbox
        "dbghelp.dll",    // (could indicate a debugger present if loaded unusually)
        "avghookx.dll",   // AVG
        "snxhk.dll",      // Avast
        NULL
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    MODULEENTRY32 mod; mod.dwSize = sizeof(mod);
    if(Module32First(snap, &mod)) {
        do {
            for(int i=0; blacklist[i]; ++i) {
                if(_stricmp(mod.szModule, blacklist[i]) == 0) {
                    std::cout << "Detected analysis module: " << mod.szModule << "\n";
                }
            }
        } while(Module32Next(snap, &mod));
    }
    CloseHandle(snap);
}
```

This code takes a list of known hook/analyzer DLL names and checks the process modules for any matches. If found, it prints a detection message. In real malware, it might simply exit if any are found. The list in this example includes Sandboxie’s DLL, CWSandbox’s logging DLLs, common AV hook DLLs, etc. (The Al-Khaser project provides a longer list of such DLL names that malware might search for ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,dir_watch.dll%20%28iDefense%20Labs)).)

**Mitigation:** **Sandbox providers** should avoid leaving obvious “footprints” like special DLLs in the target process. Modern sandboxes try to operate without introducing custom modules. If a user-space agent is needed, it’s often given a random name or something that mimics a legitimate module. Even then, malware could detect unusual modules, so minimizing loaded modules is best. **Analysts** running malware manually should not inject tools into the process that are easily identified (for example, running the sample under Sandboxie or with certain monitoring tools will load those DLLs – better to avoid that). If you must use such tools, be aware the malware might behave differently. From a development perspective, using OS-provided frameworks (like ETW, or WMI outside the process) can gather info without injecting libraries. In summary, keep the analysis environment’s in-process footprint as slim and normal as possible.

### System API Abuse for Sandbox Detection

**How it works:** Malware can also use system APIs to gather info that indirectly indicates a sandbox. For example, calling `NtQueryInformationProcess` with `ProcessDebugPort` can tell if the process is being debugged or under a job object – some sandboxes restrict processes with job objects, which could be detectable. Another example is using `NtQuerySystemInformation` for system-wide details: a sandbox might have certain limits (like only one or two processes running, or specific job limits). If malware finds, say, that the only processes running are itself and system processes, it might suspect a sandbox. These are more heuristic and not definitive by themselves.

In addition, some sandbox products might set specific environment variables or memory values. Malware can check for those if known.

**Mitigation:** For sandbox developers, the strategy is to **avoid drastic deviations from normal system behavior**: if your sandbox uses job objects or other containment, try to use mechanisms that are transparent to the process (or at least don’t flag as a debug port or such). For example, if you use a Job, you might give it allowances so queries don’t reveal suspicious limitations. Keep the number of running processes, loaded drivers, etc., within normal ranges. **Analysts** likely can’t change these things easily but should know that malware might be checking them – if a sample only runs on a very “lived-in” system, you might need to collect data on a real host (or create an analysis VM that actually has many programs installed and running to appear busy).

## Timing-Based Evasion Techniques

Timing attacks are a classic anti-sandbox strategy. Malware can intentionally delay execution or measure time differences to detect if it’s running slower or faster than normal due to instrumentation, or if the sandbox is fast-forwarding time. They can also simply stall to outwait analysis.

### High-Resolution Timing (RDTSC Instruction)

**How it works:** The `RDTSC` instruction reads the CPU’s time-stamp counter, giving a high-resolution tick count. Malware can use it to measure small time intervals very precisely. In a VM, `RDTSC` might execute more slowly or the time may jump oddly because of VM exits. A known trick is to execute `RDTSC`, then an innocuous instruction that causes a VM exit (like `CPUID`), then `RDTSC` again ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=Timing%20Attacks%20%5BAnti)). The time difference between the two RDTSCs will be much larger on a VM (because the CPUID caused a trap to the hypervisor) than on real hardware. Malware like TDL4 and others have used this to detect virtualization by measuring timing discrepancies in the order of microseconds.

**Code (RDTSC timing):**

```cpp
#include <iostream>
#include <intrin.h>
#include <windows.h>

unsigned long long rdtsc(){
    return __rdtsc();
}

int main(){
    unsigned long long t1 = rdtsc();
    // Cause a VM exit potentially
    __cpuid((int[4]){0}, 0); // CPUID with EAX=0
    unsigned long long t2 = rdtsc();
    unsigned long long delta = t2 - t1;
    std::cout << "Delta ticks: " << delta << "\n";
    if(delta > 1000) { // threshold in ticks (arbitrary small threshold)
        std::cout << "High overhead detected (possible VM sandbox)\n";
    }
}
```

This code measures the overhead of a CPUID call. On real hardware, the difference might be, say, a few hundred cycles, whereas under a VM it could be thousands if a VM-exit occurred. The threshold of 1000 here is arbitrary; real malware might calibrate or use multiple samples to be sure.

**Mitigation:** **Sandbox devs** have a few options: (1) **Trap and manipulate RDTSC** – some hypervisors let you intercept RDTSC and you could lie about the timing to make it seem consistent. However, intercepting every RDTSC has a performance cost. (2) **Offer native execution** – advanced sandboxes might single-step or emulate only parts of execution, but let timing-critical sections run natively to preserve timing (this is complex). (3) Many sandboxes choose to ignore these subtle timing checks and instead focus on not introducing *gross* delays. Over the years, hypervisors have reduced overhead for instructions like CPUID. New virtualization extensions also provide ways to avoid trapping on CPUID if not needed. **Analysts** can try to defeat timing checks by using a very fast machine for the sandbox (so even if there is overhead, it’s minimized). If one suspects a sample is stalling via RDTSC loops, one trick is to run it under an emulator that can fast-forward the CPU counter or patch the binary to remove those loops. In general, though, modern malware might combine timing checks with others, so mitigating just this may not be enough.

### Sleep and Clock Skew Detection

**How it works:** A common sandbox evasion is simply calling `Sleep` for a long time (minutes or hours) to see if the sandbox will fast-forward or terminate the analysis early. Many sandboxes instrument or modify Sleep to skip long waits. Malware can detect this by comparing real time before and after sleeping. For example, call `GetTickCount` or `QueryPerformanceCounter`, then Sleep for 10 seconds, then check the clock again. If the reported elapsed time is much less than expected (or zero), the sandbox likely skipped the sleep. Some malware use shorter repeated sleeps to accumulate a delta and catch acceleration ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=%2A%20Sleep%20,IcmpSendEcho%20%28CCleaner%20Malware)) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,CreateWaitableTimer)). Others use alternate timers like `SetTimer` or `NtDelayExecution` to see if those are hooked ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,NtWaitForSingleObject)).

**Code (Sleep acceleration check):**

```cpp
#include <windows.h>
#include <iostream>
int main() {
    DWORD t1 = GetTickCount();
    Sleep(5000); // sleep 5 seconds
    DWORD t2 = GetTickCount();
    DWORD elapsed = t2 - t1;
    std::cout << "Elapsed by clock: " << elapsed << " ms\n";
    if(elapsed < 4000) {
        std::cout << "Detected accelerated sleep (sandbox likely)\n";
    } else {
        std::cout << "Normal sleep behavior\n";
    }
}
```

If a sandbox skips or fast-forwards the Sleep, the `GetTickCount` difference might be very small (or the same, if they froze the tick count). Normal behavior would be around 5000ms (give or take scheduling). Malware Locky had a variant of this: it performed a Sleep, but also did some meaningless work with `GetProcessHeap` and `CloseHandle` around it to thwart naive API hooking of Sleep ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,NtWaitForSingleObject)).

**Mitigation:** **Sandboxes** face a dilemma: either let malware sleep (delaying analysis) or skip it and risk detection. A common mitigation is to **skip sleeps but also adjust the system clock** forward by the same amount, so from the program’s perspective time advanced normally. Sandboxes can hook `GetTickCount`, `QueryPerformanceCounter`, etc., to add the skipped time offset. This must be done consistently across all time sources to avoid tipping off the malware. Another approach is to reduce the sleep intervals by a factor (e.g., make a 5s sleep actually 1s, but that’s detectable if the program measures absolute time). The more robust approach is clock manipulation: ensure that if you accelerate Sleep, you also make the observed time jump. This can be tricky but is implemented in some analysis systems. **Analysts** running manually can simply wait out the sleep or patch the malware binary to remove long sleeps (if they suspect a sample is just stalling, a quick patch to the Sleep call or altering its parameter can force it to proceed). Being patient is a valid strategy too – if you have the time, letting the malware actually sleep will defeat its attempt to outrun a sandbox.

### Multi-Stage Delays and Triggers

**How it works:** Some malware avoid doing anything interesting for an extended period or until certain conditions are met (not necessarily human interaction, but time-based triggers). For example, the malware might check system uptime and only activate after the machine has been on for a few hours. In a sandbox that boots a fresh VM (uptime low), the malware would never run its payload. Another technique is performing expensive computations (like huge loops or solving complex math problems) to waste time. Recently, malware like **LummaC2** introduced a novel twist: using complex mathematical operations (trigonometry) as a time-delay that also serves as a human-check (discussed in the next section) ([LummaC2 Malware Deploys New Trigonometry-Based Anti ...](https://thehackernews.com/2023/11/lummac2-malware-deploys-new.html#:~:text=LummaC2%20Malware%20Deploys%20New%20Trigonometry,principle%20of%20trigonometry%20to)). The idea is that a sandbox might cut off if CPU usage is pegged for too long with no output.

Malware might also chain multiple small sleeps or yield calls (`SwitchToThread`, `NtYieldExecution`) repeatedly, which might evade simple hooking that only patches Sleep calls ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,module%20bounds%20based)).

**Mitigation:** Many of these delays can be handled by **increasing sandbox analysis time** (run malware longer) or detecting loops by monitoring CPU usage (if the sample uses near 100% CPU for a sustained time doing nothing I/O-related, the sandbox could suspect a delay loop and try to handle it by speeding up or breaking out). For analysis, **dynamic binary translation** frameworks can sometimes skip over long loops. **Sandbox devs** have experimented with measuring instruction retirement count – if an insane number of instructions executed with no interesting behavior, maybe break out of the loop. But this is advanced and not widespread. A practical mitigation is to simply allow more time for analysis or have a second phase where the sandbox picks up the process after a while (some sandboxes take memory snapshots and can resume execution later, or use checkpointing to let time pass quicker). As an analyst, recognizing such patterns (e.g., malware sits idle or in computation) might mean you need to intervene (with a debugger to skip the loop) or just wait it out if feasible.

### Network and External Timing Checks

**How it works:** Some malware use external resources to detect sandboxing. For instance, they might attempt a network connection (like `IcmpSendEcho` ping as seen in some malware ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=%2A%20WaitForMultipleObjects%20,CreateTimerQueueTimer))) and measure response time or check if it’s blocked. A sandbox might simulate network or have no network; if malware expects a certain behavior (like an internet connection) and doesn’t see it, it may not proceed. Timing-wise, if a sandbox accelerates Sleep but not network APIs, the malware might notice that its Sleep 5 seconds felt short but a real network request still took real time (inconsistency). There are also cases where malware checks the latency of certain operations (file access speed, network speed) to guess if it’s in a constrained environment.

**Mitigation:** **For sandbox developers**, providing a realistic network environment is important. Ensure that network calls succeed (even if to a sinkhole) rather than always time out instantly (which could signal an isolated sandbox). Keep consistency in how time flows for all operations. It’s difficult to cover every edge case, but general principle: don’t let the malware observe glaring inconsistencies (like time jump for Sleep but not for other waits). **Analysts** using sandbox services might try running the sample with internet access on vs off to see differences. If a sample seems inert, it might be waiting for a network response that never comes in an offline sandbox; giving it a dummy internet connection or simulating the expected server can coax it into action.

## Environment & Configuration Detection Techniques

These techniques involve inspecting the system’s configuration, hardware, and software environment for clues of virtualization or sandboxing. Malware often combines many of these checks to build confidence that it’s not on a normal user’s machine.

### Registry Artifacts of Virtualization

**How it works:** Virtualization software leave footprints in the Windows Registry. Malware can query specific keys/values known to be present on VMs ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=Check%20Registry%20Keys%20B0009,%5B5)). Examples include:

- **VirtualBox:** Keys under `HKLM\HARDWARE\ACPI\DSDT\VBOX__` and similar for FADT and RSDT (ACPI tables labeled "VBOX__") ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,SYSTEM%5CControlSet001%5CServices%5CVBoxVideo%20%28VBOX)), or `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions` ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,VMware%20Tools%20%28VMWARE)).
- **VMware:** Keys like `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,SOFTWARE%5CWine%20%28WINE)), or in hardware device map: `HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\...Target Id 0\Logical Unit Id 0\Identifier` containing "VMWARE" ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,SYSTEM%5CControlSet001%5CControl%5CSystemInformation%20%28SystemProductName)).
- **Others:** `HKLM\SYSTEM\ControlSet001\Control\SystemInformation\SystemProductName` often is "VMware Virtual Platform" on VMware ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,Registry%20Keys%20artifacts)), or "VirtualBox" for VirtualBox, etc.

Malware uses Windows API (like `RegOpenKeyEx` and `RegQueryValueEx`) or WMI to check these. If it finds values containing strings like "VBOX", "VMware", it knows it’s in a VM. For instance, one technique is simply searching the entire registry for those substrings (though that’s slower).

**Code (registry check example):**

```cpp
#include <windows.h>
#include <iostream>

bool RegistryKeyExists(HKEY root, const char* subkey) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey);
    if(result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

int main(){
    const char* vboxKey = "HARDWARE\\ACPI\\DSDT\\VBOX__";
    const char* vmwareKey = "SOFTWARE\\VMware, Inc.\\VMware Tools";
    if(RegistryKeyExists(HKEY_LOCAL_MACHINE, vboxKey)) {
        std::cout << "VirtualBox ACPI key present (VM detected)\n";
    }
    if(RegistryKeyExists(HKEY_LOCAL_MACHINE, vmwareKey)) {
        std::cout << "VMware Tools key present (VM detected)\n";
    }
}
```

This sample checks two known keys (one for VirtualBox, one for VMware). There are many such keys; malware may check a whole list of them ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=3,vmwvmcihostdev%20%E2%80%A2SYSTEM%5CCurrentControlSet%5CControl%5CVirtualDeviceDrivers)). If any exist, it concludes it’s running in that VM environment.

**Mitigation:** **Developers of analysis VMs** can attempt to remove or alter these registry entries. For example, not installing VMware Tools in the sandbox VM will avoid the VMware Tools key, but then you lose the utility of those tools (trade-off). Some keys (like ACPI entries) might be unavoidable as they’re created by virtual hardware. However, one can spoof them – e.g., VirtualBox allows customizing the DMI strings so they don’t read "VBOX". Using such features, sandboxes can try to use generic values (make the VM identify as a Dell or other vendor in those keys). Note that sophisticated malware might look for *absence* of expected genuine values too, but generally, removing obvious VM references helps. **Researchers** setting up VMs can use public guides on hardening VMs (which suggest editing registry, using tools like RedPill Detect to scan your VM for obvious markers and then mitigating them). If a particular sample is known to check a certain key, an analyst might temporarily create that key on a real system to see if the malware aborts (as a way to confirm its checks). But overall, to get malware to execute, we want to hide these keys in the sandbox.

### Virtual Hardware Devices and Drivers

**How it works:** Malware can enumerate hardware devices via SetupAPI or other means and look for names that match virtual hardware. For example, listing the disk drives might reveal a model string "VBOX HARDDISK" or "VMware Virtual disk". Listing PCI devices might show vendor IDs that belong to VMware or VirtualBox. Similarly, malware might attempt to open known device interfaces: for instance, `\\.\VBoxMiniRdrDN` or `\\.\HGFS` (VMware shared folder device) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=)). If those device objects exist, it’s a giveaway. It can also check driver names loaded in the OS: e.g., by using `EnumDeviceDrivers` or querying the Service Control Manager for known driver services like "VBoxGuest" or "vmicheat" etc.

Some known driver/service names:
- VirtualBox drivers: VBoxMouse, VBoxGuest, VBoxSF, VBoxVideo, etc. ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=%2A%20,system32%5Cvboxogl.dll)) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,SYSTEM%5CControlSet001%5CServices%5CVBoxVideo%20%28VBOX)).
- VMware drivers: vm3dmp, vmci, vmmemctl, vmmouse, vmhgfs, etc. ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=%2A%20,%2A%20Directories%20artifacts)) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=%2A%20,%2A%20Directories%20artifacts)).
- These can be found in `SYSTEM\CurrentControlSet\Services` or via `EnumServicesStatus` API.

**Code (device and driver check example):**

```cpp
#include <windows.h>
#include <iostream>

// Try opening a device by name
bool DeviceExists(const char* deviceName) {
    HANDLE h = CreateFileA(deviceName, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if(h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return true;
    }
    return false;
}

int main(){
    if(DeviceExists("\\\\.\\VBoxGuest")) {
        std::cout << "VBoxGuest device present (VirtualBox detected)\n";
    }
    if(DeviceExists("\\\\.\\HGFS")) {
        std::cout << "HGFS device present (VMware shared folder detected)\n";
    }
    // Check for a known driver in memory by loading its module
    HMODULE mod = GetModuleHandleA("vmmouse.sys");
    if(mod) {
        std::cout << "vmmouse.sys loaded (VMware detected)\n";
    }
}
```

This tries to open `\\.\VBoxGuest` (a device interface for VirtualBox guest additions) and `\\.\HGFS` (VMware host-guest file system). It also checks if the VMware mouse driver is loaded. Malware can use similar approaches or more systematic ones (like SetupDiEnumDeviceInfo for disk class GUID and check device names ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,System%20Firmware%20Tables))). If any of these indicate virtualization, it can act.

**Mitigation:** **Sandbox maintainers** can hide or remove these artifacts. For instance, if shared folders aren’t needed, disable that feature so `\\.\HGFS` doesn’t exist. If possible, install generic drivers in place of VM-specific ones (some VMs allow using basic drivers that don’t expose obvious names, at some cost of performance). Renaming drivers is not trivial because they’re expected by the hypervisor, but one could potentially hex-edit the displayed name (not commonly done). Using older or alternative virtual hardware can sometimes help (e.g., using a generic E1000 NIC instead of the default VM NIC if the default has a blatant name). **Analysts** can try running the malware in a more “bare” VM – e.g., not installing guest additions, so fewer virtual devices exist. However, note that absence of those might cause other differences (like poor display resolution) that malware might notice. It’s a cat-and-mouse game. A balanced approach is to carefully choose which features to enable: enough to analyze malware but not so many that obvious strings are present. Monitoring the malware’s attempts (using tools like Procmon or Sysmon) can also tell you which device or registry it checked, so you can address that specifically next run.

### Process and Service Enumeration

**How it works:** As mentioned earlier, malware will look for processes indicative of a VM or sandbox. Beyond just checking for analysis tool processes, it specifically looks for processes like `vboxservice.exe` or `vmtoolsd.exe` that are the guest additions/services for VirtualBox and VMware ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=)) ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=4,exe)). If those are running, the environment is clearly a VM. Malware can call WinAPI (`CreateToolhelp32Snapshot` to list processes, or WMI `Win32_Process` query) to get all running processes and compare names.

Similarly, enumerating Windows services by name can reveal things like "VBoxService" or "VMTools" in the service list ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=6)). If found, that’s a dead giveaway.

**Code (process check example):**

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
int main(){
    const char* vmProcesses[] = {"vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe", NULL};
    bool vmProcFound = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if(Process32First(snap, &pe)) {
        do {
            for(int i=0; vmProcesses[i]; ++i) {
                if(_stricmp(pe.szExeFile, vmProcesses[i]) == 0) {
                    std::cout << "Found VM process: " << pe.szExeFile << "\n";
                    vmProcFound = true;
                }
            }
        } while(Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    if(vmProcFound) {
        std::cout << "VM environment detected via process list.\n";
    }
}
```

This scans running processes for typical VirtualBox and VMware process names ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=retrieve%20this%20info%20in%20multiple,exe)). (In reality, one might maintain a larger list including processes from other virtualization software or known sandbox agent processes.)

**Mitigation:** **To avoid detection,** a sandbox could choose to not run these services, but then you lose functionality (e.g., no clipboard sync if you kill VMware Tools). Another approach is renaming: one could try to rename the service executables to something inconspicuous. However, VMware Tools is hard-coded to its service names, so that’s non-trivial. Instead, some sandboxes opt not to use official guest additions and rely on their own mechanisms or nothing at all. For example, they might tolerate lower performance or use VNC for viewing the VM rather than the high-performance VM drivers. This removes those processes at the cost of convenience. **Analysts** can create VMs where these services are disabled when running malware. If a sample is known to look for `vboxservice.exe`, you can stop that service before execution. The trade-off is that certain features (like shared folders, time sync) provided by those services won’t be active – but those could themselves expose the environment. In summary, minimize obvious VM-specific processes: either disable them or use a different approach that doesn’t require them.

### Hardware Fingerprints (CPU Cores, Disk Size, Peripherals)

**How it works:** Malware often checks if the machine’s specifications are oddly low or too "clean". We saw memory; similarly, **CPU core count** is a factor. Many VMs (especially older sandbox VMs) have only 1 virtual CPU by default. A single CPU machine in 2025 is rare, so malware flags that ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=virtual%20environment%20is%20suspected,related%20to%20Unprotect%20technique%20U1340)). It can call `GetSystemInfo` or WMI `Win32_ComputerSystem` (NumberOfProcessors property) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,DLL%20Exports%20and%20Loaded%20DLLs)). 

Disk size is another. Sandboxes might use small disks (e.g., a 40GB virtual disk). Modern systems often have hundreds of GB or more. Malware can use `GetDiskFreeSpaceEx` or `IOCTL_DISK_GET_LENGTH_INFO` to get total disk size and compare to some threshold (one source suggests less than 80GB might be considered suspiciously small) ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=determine%20whether%20the%20machine%20has,Different%20aspects%20of%20the%20hardware)). 

Checking for absence of typical peripherals: for example, no printer installed might be a red flag in some malware logic ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=Modern%20Specs%20Check%20,Checks)). A real corporate machine often has some network printers or at least default PDF printer. No printers at all could mean a fresh VM. Another example: keyboard layout – some banking trojans check if the system keyboard layout is one that a real user in the target region would have. If it’s the default "EN-US" on a machine that’s supposed to be in Brazil, it might guess sandbox (or simply not the target user) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,Known%20Sandbox%20hostnames%20and%20usernames)).

**Code (core count and disk size example):**

```cpp
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>

int main(){
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if(si.dwNumberOfProcessors < 2) {
        std::cout << "Only " << si.dwNumberOfProcessors << " CPU core - possibly VM\n";
    }

    ULARGE_INTEGER freeBytes, totalBytes;
    if(GetDiskFreeSpaceExA("C:\\", NULL, &totalBytes, &freeBytes)) {
        unsigned long long totalGB = totalBytes.QuadPart / (1024ULL*1024*1024);
        std::cout << "C: drive size: " << totalGB << " GB\n";
        if(totalGB < 80) {
            std::cout << "Disk size is small ("<< totalGB <<"GB) - likely VM\n";
        }
    }
}
```

This prints the number of CPU cores and C: drive size, flagging if cores <2 or disk <80GB ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=determine%20whether%20the%20machine%20has,Different%20aspects%20of%20the%20hardware)) ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=Modern%20Specs%20Check%20,substandard%20specifications%20indicates%20a%20virtual)). It’s a simplistic check, but many malware do exactly this kind of basic profiling.

**Mitigation:** **Configure the VM to look like a normal machine.** That means giving it at least 2 CPU cores (if not 4 or 8 to mimic a high-end system). Allocate a larger disk (or at least make Windows think it has a large disk – you can resize the virtual disk or attach a second disk). Perhaps actually fill the disk with some data so it’s not entirely empty (an empty 100GB disk might also look odd, but less so than a tiny disk). Install virtual printers or dummy devices to simulate a more complete environment (adding a fake printer or two can be done via Windows settings and doesn’t require actual hardware). Set the keyboard layout and locale to match what a real user would have (for instance, if analyzing malware targeting Europe, set the VM’s locale and keyboard appropriately). Essentially, **avoid default or sparse configurations**. Sandboxes are getting better at this, often randomizing these values or using templates of real user setups. **Analysts** setting up custom VMs should also consider this: it might mean the difference between malware revealing itself or staying dormant.

### Network Adapter MAC and IP Checks

**How it works:** Virtual machine network adapters often have MAC addresses with specific OUI (organizationally unique identifiers) prefixes. For instance, VMware commonly uses MAC starting with `00:50:56`, `00:0C:29`, `00:05:69`, etc., and VirtualBox uses `08:00:27` ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=2,VirtualBox)). Malware can retrieve the MAC addresses of the system’s adapters (via `GetAdaptersInfo` or WMI `Win32_NetworkAdapterConfiguration`) and compare against known VM prefixes ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=2,VirtualBox)). If it finds a match, it knows it’s likely in a VM.

Additionally, some sandbox environments might use non-routable or unusual IP ranges consistently (though this is less reliable). More directly, some malware try to perform a reverse DNS lookup of their own IP or check hostnames to see if they are in known cloud/sandbox ranges.

**Code (MAC address check):**

```cpp
#include <iostream>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

int main() {
    IP_ADAPTER_INFO info[10];
    DWORD bufLen = sizeof(info);
    if(GetAdaptersInfo(info, &bufLen) == ERROR_SUCCESS) {
        for(PIP_ADAPTER_INFO p = info; p; p = p->Next) {
            BYTE* mac = p->Address;
            // Check first 3 bytes of MAC
            if(mac[0]==0x00 && mac[1]==0x0C && mac[2]==0x29) {
                std::cout << "VMware MAC address detected: " 
                          << p->Description << "\n";
            }
            if(mac[0]==0x08 && mac[1]==0x00 && mac[2]==0x27) {
                std::cout << "VirtualBox MAC address detected: " 
                          << p->Description << "\n";
            }
        }
    }
}
```

This uses `GetAdaptersInfo` to iterate network adapters and prints if a MAC matches VMware’s `00:0C:29` or VirtualBox’s `08:00:27` prefix. (In reality, one would include all known prefixes ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=%2A%20,%28Hybrid%20Analysis)).)

**Mitigation:** **To mitigate**, one can manually set the MAC addresses of virtual adapters to something other than the defaults. Both VMware and VirtualBox allow setting a custom MAC (preferably one that belongs to a common hardware vendor). Sandboxes often randomize MACs to not use the known OUIs. This is a simple but effective step. **Analysts** should ensure their VM’s MAC isn’t the obvious `08:00:27` etc., when possible. If using NAT network, VirtualBox might auto-generate MACs with its prefix unless changed. Also, having the VM join a network domain or have a host name that isn’t obviously generic can help (though malware also checks hostnames, see next technique). In short: use realistic MAC and network config. One caveat: some licensing or activation might be tied to MAC addresses, but as long as it’s unique, any prefix is fine from a technical perspective.

### Hostname, Username, and Other Local Identifiers

**How it works:** Many public sandboxes or corporate images have default hostnames like `WIN-ABC123` or `Sandbox` or known patterns (e.g., "MalwareAnalysisPC"). Similarly, default usernames like `Admin` or `User` that haven’t been changed can indicate an analysis environment. Malware may retrieve the computer name (`GetComputerName` API) and username, and check against a list of known sandbox indicators or just flag very generic names. There have been cases of malware that refuse to run on machines with "SANDBOX" or "MALWARE" in the name.

Moreover, malware might look at the Windows product ID or registration info – some sandboxes use the same Windows image cloned many times, so the OS product ID might be identical across them. If malware sees a product ID known from analysis reports, it could bail.

**Mitigation:** **Use unique, innocuous names.** Sandbox providers often randomize the hostname for each analysis or use something inconspicuous (like a common first-name-PC or random string that doesn’t scream VM). Same with the username – use a normal first name or typical corporate username. It’s also wise to actually **use the machine** a bit or at least simulate usage: create some documents in "Recent Files", set a custom wallpaper, etc. (These fall into human interaction category but are relevant here as static artifacts.) The goal is to avoid the appearance of a template VM that was never touched by a human. **Analysts** setting up VMs can easily change the hostname to something boring like `JOHNS-PC` and create a user account that isn’t the built-in "Administrator". Small details like having a browser history or some files in Downloads can make a difference for certain checks.

### Human Interaction and User Activity Checks

**How it works:** This is a growing category (and overlaps with the next section). Malware assumes that sandbox VMs often lack genuine user activity. So it checks for signs of a human: mouse movement, keyboard inputs, opened files, etc. One simple check is to see if the mouse has moved at all since boot or in the last few seconds ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=LummaC2%20v4,not%20emulate%20mouse%20movements%20realistically)). Another is to open a GUI dialog and see if a user clicks a button or types something (automated sandboxes typically won’t). Some malware count objects like the number of files in "Documents" or how many browser favorites or cookies exist – a very low count suggests a fresh VM ([Navigating the Vast Ocean of Sandbox Evasions](https://unit42.paloaltonetworks.com/sandbox-evasion-memory-detection/#:~:text=There%E2%80%99s%20a%20vast%20number%20of,we%20can%20do%20about%20them)). 

**Example:** The LummaC2 stealer v4 introduced a sophisticated anti-sandbox: it waits for rapid **mouse movements** and then uses geometry to determine if the movement is human-like ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=The%20malware%20first%20starts%20by,different%20from%20the%20initial%20one)) ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=After%20these%205%20cursor%20positions,all%20consecutive%20cursor%20positions%20differ)). It collects 5 cursor positions over short intervals and computes the angles between successive movement vectors. If the angles don't reflect natural human motion (for instance, if the movement was too straight or too consistent, as might happen with automated cursor movement), it concludes no real user is present and loops, waiting longer ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=forever%20until%20all%20consecutive%20cursor,positions%20differ)) ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=LummaC2%20v4,different%20angles%20that%20are%20calculated)). This prevents execution in sandboxes that only simulate minimal or periodic mouse activity.

Another check: looking at the system uptime and last input time. If the system booted just 2 minutes ago and no input has happened, it might be a sandbox that just started.

**Code (mouse movement check):**

```cpp
#include <windows.h>
#include <iostream>
int main(){
    POINT p0, p1;
    GetCursorPos(&p0);
    Sleep(300);
    GetCursorPos(&p1);
    if(p0.x==p1.x && p0.y==p1.y) {
        std::cout << "No mouse movement detected in 300ms\n";
        // (Malware might loop here until movement)
    } else {
        std::cout << "Mouse moved: ("<< p0.x<<","<<p0.y<<") -> ("<<p1.x<<","<<p1.y<<")\n";
    }
}
```

This simple snippet checks if the mouse moved in a 0.3 second window ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=The%20malware%20first%20starts%20by,different%20from%20the%20initial%20one)). Real malware would continue only when sufficient movement is observed. LummaC2 did a more complex analysis of movement shape, but the principle of waiting for *any* movement is common.

**Mitigation:** **Sandboxes** have started to incorporate pseudo-human behavior. This can mean scripting the VM to move the mouse cursor randomly, click on things, or simulate typing. However, as LummaC2 shows, malware may look for *quality* of movement, not just existence. So sandboxes are exploring more realistic interaction simulation (e.g., replaying recorded human input patterns). Another mitigation is to **feed the malware with pre-recorded inputs** if you detect it’s waiting – for example, if it’s polling cursor positions, the analysis system could generate some mouse events to satisfy it. Some advanced solutions integrate with the hypervisor to fake input at the VM level. 

On the simpler side, **analysts** can manually intervene: if you suspect malware is hung waiting for input, you can click around or move the mouse in the VM yourself. This often kickstarts the malware. There are also tools to simulate user activity (like Cuckoo sandbox has options for mouse movement). For environment preparation: having a non-default wallpaper, some random files, and some evidence of past activity (recent documents, etc.) will satisfy checks for user artifacts ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=specific%20frequencies%20commonly%20used%20in,be%20a%20virtualized%20machine%20and%2For)). Essentially, make the VM look “lived in”. For the very advanced checks like Lumma’s trigonometry, one might need to actually use the machine naturally for a bit or find a way to inject a realistic mouse trajectory. Mitigating that specifically might involve updating sandbox scripts to sometimes jiggle the mouse in curvy motions rather than straight lines. 

In summary, the more human your sandbox appears, the fewer of these checks will trip. It’s a challenging area but increasingly important as malware authors innovate in detecting sterile environments.

## User Interaction-Based Evasion

(We’ve already touched on human input, which overlaps here.) These techniques explicitly require human action or simulate user presence beyond just passive checking.

### Dialogs and Message Boxes

**How it works:** Some malware will pop up a message box or a dialog (perhaps a fake error: "This program cannot run, click OK to continue") and wait for the user to click OK. Automated sandboxes might either time out on this (if they don’t automatically press the button) or have an auto-dismiss that might be detectable (like if it disappears too fast consistently). By requiring a click, the malware ensures a human is behind the keyboard. This isn’t super common in widespread malware because it’s noisy, but it has been seen in targeted attacks or in strains that really try to avoid automated analysis.

**Mitigation:** Sandboxes can handle this by either automatically clicking default buttons after a delay or by instrumenting the GUI. However, if malware measures the delay or expects a random human response, auto clicking could be a tell. Some analysis systems will screenshot such dialogs and pause, requiring an analyst to manually intervene (which defeats full automation but ensures progress). For researchers running samples manually, of course, just clicking through will solve it.

### Keyboard and UI Interaction

**How it works:** Besides mouse, malware might check keyboard input (e.g., using `GetAsyncKeyState` to see if any key has been pressed recently, or `GetLastInputInfo` to see how long the system has been idle). If the system has been idle since boot or for an unnaturally long time, it might suspect no user. Some ransomware, for example, avoid running if certain user activity is not present, to evade sandboxes.

Another trick: checking if the **foreground window** or user’s active window is something like Task Manager or an analysis tool (some malware assume if Task Manager is open or a disassembler window is active, it’s being watched and will shut down).

**Mitigation:** For sandboxes, simulating key presses or at least updating the “last input time” can help. Setting the foreground window to some decoy (like a fake Word document) might also make the malware think the user is doing something else. In practice, ensuring the VM isn’t just sitting completely idle is key.

### Complex Human-Behavior Checks (LummaC2 example)

We already covered LummaC2’s advanced check using cursor trajectory analysis ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=At%20this%20point%20we%20know,will%20never%20detonate%20the%20malware)) ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=LummaC2%20v4,different%20angles%20that%20are%20calculated)). This represents a new frontier where malware doesn’t just check for presence of activity, but analyzes the pattern. Mitigating this requires a similarly advanced approach on the sandbox side: e.g., capturing real user mouse movement patterns and replaying them in the sandbox to produce organic-looking input. Alternatively, if the sandbox can detect the malware is spending a lot of time in these checks (via traces), it might bypass that logic by patching or by short-circuiting the analysis.

**Mitigation (advanced):** A possible mitigation for this is using **machine learning to generate human-like input** or even involving a human in the loop (some services might eventually use Mechanical Turk style human interaction for a few seconds on suspicious samples, though that raises its own issues). For now, sandbox devs are likely implementing deterministic scripts (like move mouse in a curve). As these checks are still relatively rare, a combination of simpler mitigations (moving mouse and pressing keys in random intervals) might work for most cases except the truly novel ones like Lumma’s.

## Mitigation Strategies Summary

We interwove mitigations above, but to summarize in a broader sense for both cybersecurity researchers and sandbox developers:

- **Resource Realism:** Configure analysis VMs with realistic hardware specs (CPU cores, RAM, disk, devices). Avoid obviously low or exact values ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=Modern%20Specs%20Check%20,substandard%20specifications%20indicates%20a%20virtual)) ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=determine%20whether%20the%20machine%20has,Different%20aspects%20of%20the%20hardware)). Use common device names and remove or replace any with "Virtual" in them.

- **Stealth Monitoring:** Use out-of-guest or less detectable methods to monitor malware ([Navigating the Vast Ocean of Sandbox Evasions](https://unit42.paloaltonetworks.com/sandbox-evasion-memory-detection/#:~:text=The%20gold%20standard%20for%20preventing,byte%20anywhere%20in%20the%20OS)). Hypervisor-level hooking, network monitoring, etc., leave fewer traces than injecting DLLs or patching code in the malware process.

- **Artifact Scrubbing:** Remove or alter known VM artifacts (registry keys, file paths, process names) whenever possible ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=3,vmwvmcihostdev%20%E2%80%A2SYSTEM%5CCurrentControlSet%5CControl%5CVirtualDeviceDrivers)) ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=4,exe)). This includes not only virtualization markers but also analysis tool traces. Tools like Al-Khaser’s list or community scripts can help identify such artifacts in your VM environment to address them.

- **Time Manipulation:** If accelerating malware execution (skipping sleeps), do so consistently and transparently (advance clocks to match). Alternatively, allocate longer runtime to catch late execution.

- **Interaction Simulation:** Invest in simulating user activity – moving mouse, typing, changing window focus, even browsing a bit. This counters checks for human presence ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=LummaC2%20v4,not%20emulate%20mouse%20movements%20realistically)) ([mbc-markdown/anti-behavioral-analysis/virtual-machine-detection.md at main · MBCProject/mbc-markdown · GitHub](https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/virtual-machine-detection.md#:~:text=specific%20frequencies%20commonly%20used%20in,be%20a%20virtualized%20machine%20and%2For)). 

- **Environment Diversity:** Don’t use identical snapshots for every analysis. Randomize things like MAC addresses ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=2,VirtualBox)), hostnames, user profiles, and even OS versions across analysis runs if feasible. This way, malware cannot have a single easy check that works everywhere.

- **Monitoring Evasions:** As a researcher, monitor the malware for signs it’s checking these things. Tools (like API monitors, debugger with log breakpoints on suspicious APIs) can reveal “the malware tried to read CPUID or opened \\.\VBoxGuest”. Knowing what it’s checking helps tailor mitigations.

- **Fallback to Bare Metal:** In cases of extremely stubborn malware that detects everything, running it on a sacrificial real machine (or bare-metal sandbox) may be necessary. Solutions like bare-metal analysis (using physical hardware or more transparent hypervisors) can catch what traditional VMs miss, at higher cost.

Implementing these mitigations is a balancing act. Sandboxes must retain functionality and performance while eliminating clues that they are sandboxes. By combining multiple mitigation strategies, analysts and developers can significantly reduce the success of anti-VM, anti-sandbox techniques and thereby capture the malware’s true behavior ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=Conclusion%20Malware%20authors%20eventually%20find,security%20sandboxes%20and%20virtual%20machines)). Each time malware authors introduce a new trick, the defensive side adapts – an ongoing cat-and-mouse in the world of malware analysis.

**Sources:** This report references known techniques documented by research blogs and projects like **Al-Khaser** ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=)) ([GitHub - ayoubfaouzi/al-khaser: Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.](https://github.com/ayoubfaouzi/al-khaser#:~:text=,dir_watch.dll%20%28iDefense%20Labs)), academic and industry analyses (Unit 42, Outpost24) ([Unveiling LummaC2 stealer’s novel Anti-Sandbox technique: Leveraging trigonometry for human behavior detection](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/#:~:text=LummaC2%20v4,not%20emulate%20mouse%20movements%20realistically)) ([Navigating the Vast Ocean of Sandbox Evasions](https://unit42.paloaltonetworks.com/sandbox-evasion-memory-detection/#:~:text=The%20following%20are%20just%20a,malware%20authors%20can%20check%20for)), and community knowledge bases ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=%E2%80%A2CPUID%3A%20This%20instruction%20is%20executed,it%20will%20equal%20to%201)) ([Malware | Igor Garofano blog](https://igorgarofano.wordpress.com/category/security/malware/#:~:text=4,exe)). These sources provide real-world examples of malware employing the above methods and informed the mitigation advice presented.
