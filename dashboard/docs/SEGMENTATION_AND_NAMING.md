# Keystone presentation segmentation and naming

The dashboard separates the red-team platform from every target. A platform
node can be the current source of an engagement, but it is never counted as a
compromised target merely because the operator is using it. `g960` is always the
target-side **Guest Network Kiosk**; it is not an operator platform.

## Presentation segments

These segments organise the live map without changing VLANs, routes, firewall
rules, challenge prerequisites, or scoring:

| Segment | Purpose |
|---|---|
| Red Team Platform | Control station, portable node, relay, and staged VM |
| Network Perimeter | Edge gateway and routing boundary |
| Guest Access | Untrusted visitor and physical-access targets |
| Management Plane | Directory-adjacent management services |
| Public Services | Internet-facing business applications |
| Automation Services | Job and workflow systems |
| User Workstations | Employee endpoints |
| Business Data | Finance, HR, and shared-file systems |
| Application DMZ | Service hosts and their application pods |
| Privileged Services | Executive and high-trust internal applications |
| Identity Services | Domain and identity infrastructure |

## Naming rules

- Use a business role for the visible label: `Finance Workstation`, not `emp01`.
- Keep the real hostname and VM/container identifier in the inspector.
- Use numbered names only for genuine peers: `DMZ Web Host 01` and `02`.
- Do not put a tool or product name in a target label.
- Use `Red Team Control Station`, `Portable Red Team Node`, `Command Relay`, and
  `Staged Operator VM` for platform roles. The active one is selected by run
  telemetry, not inferred from the Guest Access segment.

The network remains the same four-zone Keystone enforcement model underneath.
This document governs the dashboard's presentation layer so added segmentation
improves comprehension without adding another exploitation or pivot gate.

## Portable-node drop decision

The portable red-team Pi is dual-homed and is never the Guest Network Kiosk.

- Control plane: the existing red-team LAN/Tailscale path only.
- Target-facing Ethernet: Guest Access VLAN 60, `10.99.60.0/24`.
- Proposed DHCP reservation: `10.99.60.20` after the VLAN exists.
- Allowed reachability: perimeter, public services, and application DMZ—the
  same first-stage reachability as the existing entry path.
- Denied reachability: management, user, business-data, privileged, and
  identity segments until the engagement earns a pivot.
- No routing, NAT, or bridging between the Pi's control and target interfaces.

The kiosk remains a separate target-side node on Guest Access. Dashboard
telemetry may show the Pi as the active operator location, but that never counts
the Pi as a compromised target.
