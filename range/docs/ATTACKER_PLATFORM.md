# Attacker Platform — arm64 Windows Laptop + Kali VM

## Hardware

- **Laptop:** Snapdragon X Elite (X1E80100), 16 GB RAM, Windows 10/11 Pro
- **Requirement:** Pro/Enterprise/Education SKU (Home has no Hyper-V)
- **Nested virtualisation:** supported on Snapdragon X Elite / X Elite Pro.
  Not supported on Snapdragon 8cx Gen 3.

## Architecture

```
+------------------------------------------------------------+
| arm64 Windows 11 Pro (Snapdragon X Elite)                  |
|                                                            |
|  Hyper-V (Gen 2 VM, ARM64, nested-virt on)                 |
|    +--------------------------------------------------+    |
|    | Kali Linux ARM64 (attacker VM)                   |    |
|    |   - operator shell, msfconsole, impacket-arm     |    |
|    |   - redteamscripting MCP client                  |    |
|    |   - Tailscale node → drop01 (planted Pi)         |    |
|    +--------------------------------------------------+    |
|                                                            |
|  Native Windows side                                       |
|    - RDP into Parrot host when at desk                     |
|    - OSINT browser profile for pre-engagement recon        |
+------------------------------------------------------------+
                   |
                   | Tailscale WireGuard
                   v
             drop01 Pi (planted) --- corp VLAN
```

## VirtualBox fallback (Windows 10 Home)

If the laptop runs Windows 10 Home (no Hyper-V), use VirtualBox instead:

```bash
# Existing VMs on the laptop include "kali-attack" — repurpose or create new
VBoxManage createvm --name "kali-keystone" --ostype "Debian_arm64" --register
VBoxManage modifyvm "kali-keystone" --memory 4096 --cpus 4
VBoxManage modifyvm "kali-keystone" --nic1 nat --nictype1 virtio
```

Pin a specific Kali ARM64 release for reproducibility:
https://www.kali.org/get-kali/#kali-arm

## Constraints

1. **No x86 emulation inside the VM.** The attacker VM is ARM64 only. Any
   x86-only tooling (certain Impacket consumers, older msfvenom encoders)
   must run on Parrot across Tailscale.

2. **ARM64 code paths required in the MCP server.** `malware_generate` and
   `malware_polymorph` have `arch=aarch64` parameters. ARM64 shellcode uses
   SVC syscalls; ARM64 polymorphism uses NOP sled variation (`0xd503201f`)
   and register rotation instead of `shikata_ga_nai`.

3. **Kali ARM64 image verification.** Download from kali.org, verify GPG
   signature. Pin the release version in `docs/` for run reproducibility.

## Setup steps

1. Enable Hyper-V (or install VirtualBox on Home)
2. Download Kali ARM64 installer ISO
3. Create Gen 2 VM, 4 GB RAM, 4 vCPU, 40 GB disk
4. Install Kali, update, install: `impacket msfconsole responder hashcat`
5. Install Tailscale, join the lab tailnet
6. Verify connectivity: `ping drop01` over Tailscale
7. Clone keystone-range repo, configure MCP client
8. Test: `malware_generate(arch="aarch64")` produces ARM64 payload

## Benchmark value

Every current public pentest-agent benchmark assumes an x86 Linux attacker
box. Running Keystone from an ARM Windows laptop → ARM Kali VM is a real-world
setup (field operator with a travel laptop) that exposes architecture-dependent
tooling gaps. This is a feature of the benchmark, not a limitation.
