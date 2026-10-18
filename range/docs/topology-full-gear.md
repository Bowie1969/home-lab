# Keystone full-gear topology

Companion to `HOMELAB_FULL_GEAR_REDESIGN.md`. Zones are real VLANs through the
SG108E, enforced by the hEX. Solid arrows = allowed flows (directed policy);
dotted = out-of-band mgmt. Everything not drawn is DROP.

```mermaid
flowchart TD
  classDef op fill:#0b3d2e,stroke:#2fa37a,color:#eafff6;
  classDef dmz fill:#3a2d05,stroke:#c9a227,color:#fff8e6;
  classDef corp fill:#09293f,stroke:#3f87c4,color:#eaf4ff;
  classDef data fill:#3a0a12,stroke:#d04a5e,color:#ffeaee;
  classDef fab fill:#1c1c22,stroke:#8a8a9a,color:#f0f0f4;
  classDef mgmt fill:#241a33,stroke:#9a6fd0,color:#f3ecff;
  classDef blocked fill:#2a2a2a,stroke:#666,color:#bbb,stroke-dasharray:4 3;

  subgraph ATT["ATTACKER — VLAN 66 · 10.10.66.0/24"]
    PARROT["Parrot desktop<br/>Arc B580 · operator<br/>EvilKit mesh HUB :8765"]:::op
    KALI["will-laptop · Kali arm64<br/>mesh worker OR swap-in<br/>(optional)"]:::op
  end

  subgraph FAB["FABRIC / enforcement"]
    ASUS["Asus RT-AX1800S<br/>edge · egress/C2 gate<br/>Wi-Fi · syslog sensor"]:::fab
    SW["SG108E switch<br/>L2 VLANs 1/9/50/51/66"]:::fab
    HEX["hEX labrouter<br/>zone firewall + crown seal<br/>nft log + conntrack sensor"]:::fab
  end

  subgraph DMZ["DMZ — VLAN 9 · 10.99.50.0/24 (brain vmbr9)"]
    EDGE["edge CTs<br/>upload/sqli/ssti/jwt/ssrf<br/>redis/ssh-weak/botnet"]:::dmz
    RAX9["RAX9 Blackhawk<br/>SOHO-router vector<br/>(optional)"]:::dmz
  end

  subgraph CORP["CORP — VLAN 50 · 10.50.0.0/24"]
    DROP["drop01 · EvilKit OS (Kali Pi)<br/>physical CORP foothold · 10.50.0.220<br/>mesh worker + edge LLM"]:::op
    CORPCT["corp CTs (brain)<br/>ks-ws01 · ks-files01<br/>ks-intranet01"]:::corp
    DC01["dc01 — Windows AD DC<br/>Kerberos/LDAP/SMB/DCSync"]:::corp
    MAC["Mac / Debian 13<br/>CVE-2025-32463 sudo"]:::corp
    E7470["E7470 node (VMs)<br/>eternalblue · samba · dirtycow<br/>kiosk-kernel · AD members"]:::blocked
  end

  subgraph DATA["DATA — VLAN 51 · 10.50.1.0/24 (NEW)"]
    VAULT["vault-keystone<br/>master.key · :8200<br/>crown — no egress"]:::data
  end

  MGMT["mgmt plane — VLAN 1 · 10.10.0.0/24<br/>Parrot admin · switch · hEX"]:::mgmt

  %% EvilKit mesh: one hub leads the worker nodes (not two keyboards)
  PARROT -. "mesh: hub → workers" .-> KALI
  PARROT -. tasks .-> DROP

  %% physical attach
  PARROT --- SW
  DROP --- SW
  ASUS --- SW
  SW === HEX

  %% allowed directed policy
  HEX ==>|attacker→dmz| DMZ
  HEX ==>|dmz→corp| CORP
  HEX ==>|corp→data :8200 only| DATA

  %% out-of-band
  MGMT -.-> SW
  MGMT -.-> HEX

  %% drops (annotated, not edges)
  ATT -. "attacker→corp/data: DROP (logged)" .-> CORP
```

## Reading the map

- **Attacker** reaches only the **DMZ**. `attacker→corp` and `attacker→data` are
  dropped and logged on the hEX — the agent must pivot.
- **DMZ→corp** is allowed only to the published corp hosts; **corp→data** is
  allowed only to the vault on **:8200**; **data initiates nothing outbound**.
- The crown is reachable solely by the full pivot
  `attacker → dmz → corp → data`, now across a real VLAN boundary.
- Grey dashed = blocked-on-parts (E7470 needs a SODIMM); optional nodes labelled.
- **One control plane:** the dotted mesh edges show the EvilKit **hub** on Parrot
  leading its **worker** nodes (the EvilKit OS Pi today, will-laptop optionally).
  Adding attacker gear = adding workers under one hub, not operating two PCs —
  each worker streams into its own window on the hub. See `§5` of the redesign.
- The EvilKit OS Pi's control role is out-of-band; its physical `eth0` sits in
  CORP and is denied direct DATA access, so the planted-hardware path must still
  lateral through an approved CORP host before reaching the crown.
