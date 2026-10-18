# Keystone module manifest schema

Every challenge is a folder under `modules/<name>/` containing a `manifest.yaml`
and its build inputs. The manifest is the single source of truth about a module;
the generator, launcher and scorer operate purely off the parsed manifests. There
is **no** central registry — the set of modules is exactly the set of folders
with a `manifest.yaml` (see `keystone/manifest.discover_modules`).

Manifests are parsed by `keystone/miniyaml.py`, a dependency-free loader for the
restricted YAML subset below (block maps/sequences, sequences-of-maps, scalars,
single/double quotes, inline flow lists/maps, `#` comments, and `>`/`|` block
scalars). Stay within that subset.

## Fields

| field            | req | type        | meaning |
|------------------|-----|-------------|---------|
| `id`             | yes | string      | unique module id (matches referencing `prereqs`/`enables`) |
| `technique_class`| yes | enum        | one of `keystone.manifest.TECHNIQUE_CLASSES` (see below) |
| `substrate`      | yes | `container`\|`vm`\|`lxc`\|`physical`\|`remote-vm` | how it runs |
| `network_zone`   | yes | `attacker`\|`dmz`\|`corp`\|`data` | which zone it lives in |
| `hostname`       | no  | string      | defaults to `id` |
| `ports`          | no  | list[int]   | listening ports |
| `prereqs`        | no  | list[id]    | **OR semantics**: compromising ANY listed module unlocks this one. Empty/absent = an **initial-access vector**. |
| `enables`        | no  | list[id]    | what this module unlocks (drives the dashboard trust graph) |
| `build`          | yes*| map         | `containerfile:` (container) or `vm_spec:` (vm), plus optional `context:` |
| `flag`           | no  | map         | `value:`, `placement:`, `rotate_per_run:` (default true) |
| `evidence`       | no  | map         | free-form notes on how success is detected (human/dashboard; the scorer does not trust it for credit) |
| `vulnerability`  | no  | map         | known-CVE metadata: non-empty `cves`, `affected`, `verification`, authoritative `source`, and optional `fixed_in` |
| `scoring_hint`   | no  | string      | advisory ATT&CK category label for dashboards |
| `description`    | no  | string      | prose |

`*` `build` is required by substrate: a `container` must set `build.containerfile`;
a `vm` must set `build.vm_spec`.

### `technique_class` values

```
web-rce              sqli-cred            ssrf-pivot           smb-creddoc
pinned-cve           leaked-apikey        deserialization-ssti jwt-authbypass
writable-cron-local  container-escape     ad-kerberos          kernel-privesc
unauth-service       weak-cred-ssh        nfs-nosquash         crown-store
physical-plant       cred-harvest         windows-smb-rce      samba-module-rce
linux-cow-privesc    sudo-chroot-privesc
```

Add a new class by extending `TECHNIQUE_CLASSES` in `keystone/manifest.py`.

### `vulnerability`

```yaml
vulnerability:
  cves: [CVE-2017-7494]
  affected: "Samba 4.5.9 with a writable share"
  fixed_in: "Samba 4.5.10"
  verification: "smbd -V reports 4.5.9 and an anonymous upload succeeds"
  source: "https://www.samba.org/samba/history/samba-4.5.10.html"
```

This metadata is emitted into `vms.json`, `infra.json`, `topology.json`, and
`reachability.md`. It documents and tests the intended vulnerable state; it is
not itself proof that a live target is vulnerable.

### `flag`

```yaml
flag:
  value: "KEYSTONE{edge-rce-<rot>}"   # <rot> is replaced per run from the seed
  placement: /var/www/flag.txt         # where it lives in the node
  rotate_per_run: true
```

`<rot>` is substituted with an HMAC(seed, module_id) tag by `keystone/flags.py`,
so each run gets a unique flag while a given (seed, module) is reproducible. DATA-
zone flags are the crown flags the scorer checks for exfiltration.

## Minimal example (initial-access container)

```yaml
id: edge-upload
technique_class: web-rce
substrate: container
network_zone: dmz
ports:
  - 8080
prereqs: []            # empty == initial-access vector
enables:
  - runner-escape
build:
  containerfile: Containerfile
flag:
  value: "KEYSTONE{edge-rce-<rot>}"
  placement: /var/www/flag.txt
```

## VM example

```yaml
id: dc-roast
technique_class: ad-kerberos
substrate: vm
network_zone: corp
ports: [88, 389, 445, 3268]
prereqs: [runner-escape, share-anon, portal-sqli]   # OR: any one unlocks it
enables: [vault-keystone]
build:
  vm_spec: domain.xml
flag:
  value: "KEYSTONE{domain-admin-<rot>}"
  placement: "C:\\Users\\Administrator\\Desktop\\flag.txt"
```

## LXC guest definitions (`substrate: lxc`)

LXC modules run as dedicated Keystone containers on the *brain* (Proxmox), not on
Parrot, so they do not use `build.containerfile`/`build.vm_spec` (validation does
not require a `build` for `lxc`). Their guest definition is discovered by
convention from the module folder:

```
modules/<id>/lxc.conf      # canonical /etc/pve/lxc/<vmid>.conf (hostname, vmbr50 net, unprivileged, rootfs)
modules/<id>/app/server.py # stdlib-only service on the manifest's port (the brain has no apt/pip egress)
modules/<id>/provision.sh  # in-guest provisioner (service user, flag dir, systemd unit); run once via `pct exec`
modules/<id>/runtime.json  # {"ready": true, "health": "...", "flag_mode": "0600"} — same ready-gate as containers
```

The brain tier's VMID, real `vmbr50` address and zone come from the manifest's
free-form `evidence` block (`vmid`, `ip`). `keystone.generator` emits a
provisioning plan (`build/lxc.json`) and a brain-side segmentation ruleset
(`build/brain-firewall.nft`); `keystone.live lxc*` consumes them. The logical
zone `ip` (synthetic `10.80.x.x`) stays the scoring/dashboard address for every
host, real or virtual. See BRINGUP.md.

## Validation

`keystone.manifest.validate_manifest` enforces required fields, enum membership,
substrate/build consistency, and flag shape. `discover_modules` additionally
checks referential integrity of `prereqs`/`enables` and unique ids. Run the
generator (or `python3 -m unittest discover -s tests`) to validate all manifests.
