# win7-eternalblue — RETIRED (2026-10-15)

Replaced by [`../win2025-smb/`](../win2025-smb/) as the `windows-smb-rce`
module in the Keystone VM redesign.

**Why retired:** the 2026-10-15 VM redesign standardises on a modern Windows
target (Server 2025) in corp so EvilKit sees a current SMB stack. The Win7
EternalBlue path remains well-documented but no longer earns its slot: the
redesign also resolves the still-open task-2 Win2025 provisioning blocker
(CPU-flag/repair-loop) as part of the move.

**What this folder is now:** reference material only. The manifest here is
kept for history; `runtime.json` is flipped to `ready=false` so the module
discovery excludes it from live bring-up. Delete the folder entirely once
the win2025-smb module is in production and no run documentation points at
win7-eternalblue anymore.

**Do not provision this module.** `keystone.live` honours `ready=false`.
