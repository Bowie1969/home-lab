# EvilKit `patch-diff-poc` on Keystone Range

A capability note for the public release. Keystone is the controlled range;
EvilKit is the AI operator we point at it. The `patch-diff-poc` workflow lets
EvilKit reason from a published security-fix commit to a scope-gated PoC
rather than pulling third-party exploit code off the shelf.

## What the workflow is

Pipeline inside EvilKit (`evilkit/patch_diff_poc.py`):

```
public GitHub commit URL  --fetch unified diff-->  PocRecipe  --render-->  Python PoC script
```

The recipe is a dataclass of plain facts the module extracts from the diff:
affected files, removed vs added lines, parameter names that flow into a sink,
and a sink class (`eval-sink`, `template-injection`, `sqli-union`, …). The
renderer is a template library keyed on the sink class. Unknown sinks still
emit a runnable harness, but with an explicit `# TODO: payload` placeholder —
the agent is expected to fill it, not pretend it is complete.

Every generated script does three things before it sends a request:

1. Parses `--target <base-url>` and splits scheme / host / port.
2. Reads a `--scope-file` allow-list (same shape as `evilkit scope show`) and
   refuses to run if the target host is not listed. Refusal exits `3` with
   `REFUSED` and sends nothing.
3. Writes a small JSON evidence record (`status`, `hit`, `body_head`) next to
   the script. That record is the artefact the operator files into the run
   journal.

## What it is not

- **Not an exploit-DB mirror.** The module never fetches third-party exploit
  scripts, Metasploit modules, or public PoCs. The only outbound call is to
  `https://api.github.com` for the commit payload the operator named.
- **Not a vendor advisory crawler.** It takes exactly one input: the commit
  URL the operator passes. It does not try to resolve a CVE to a commit on
  its own.
- **Not an unscoped runner.** The generated client refuses to touch anything
  outside the operator's allow-list, including on a mistyped `--target`.
- **Not a judgement about the fix.** The module reasons from the diff only.
  If the fix is incomplete the module cannot know, and the generated PoC
  may still miss. The recipe JSON is deliberately readable so the operator
  can see every fact the renderer used.

That distinction matters for a CEO demo: EvilKit is doing patch-informed
reverse engineering, not shipping exploits other people wrote. On the
Keystone range the same scope-gate protects the lab from a mistake.

## Demo path

The committed demo is `scripts/evilkit-patchdiff-demo.sh`. It fires at the
Keystone `legacy-cve` pod (pinned Pillow 8.3.2, reachable at
`10.99.50.114:8082` on a healthy range).

```
bin/launch.sh                                   # bring the range up
EVILKIT_SRC=~/evilkit scripts/evilkit-patchdiff-demo.sh
```

The script performs five stages:

1. Writes a one-host scope allow-list in the run directory.
2. Health-probes the target. Fails fast if the range is not reachable.
3. Runs `evilkit patch-diff-poc` on the public CVE-2022-22817 fix commit on
   `python-pillow/Pillow`. The commit URL is the only external fetch.
4. Fires the generated script at the authorised target through the scope
   file. On a healthy range this returns a rotated flag of the form
   `KEYSTONE{...}` written into the pod by `bin/reset.sh`.
5. Re-runs the same script against an out-of-scope address
   (`10.0.0.1:8082`). The expected result is exit `3`, `REFUSED`, with no
   request sent — i.e. the scope gate is proved from the attacker side.

Artefacts land under `runs/patchdiff-demo-<timestamp>/`:
`poc_python-pillow_Pillow_*.py`, its `.recipe.json`, `evidence.json`, and
`scope.txt`.

## Dashboard visibility

The lab dashboard renders three script-lifecycle events against the target
node card: `script_authored` (EvilKit wrote the script), `script_uploaded`
(the script now sits on the host), `script_executed` (it ran there). See the
"Red-team script lifecycle" section of the Keystone `README.md` for the exact
telemetry calls. During the demo these three events paint the `legacy-cve`
node from tier 3 (foothold) to tier 4 (operating) in real time, which is what
you want the Baidam audience to see.

## Why this maps to the expanded range

The 2026-10-16 range expansion added three new vulnerable-container modules
on the CORP VLAN. Each one is a sink class the `patch-diff-poc` workflow is
built to exercise:

| Module | Technique class | Sink class |
|---|---|---|
| [modelhub-pickle](../modules/modelhub-pickle/manifest.yaml) | ai-supply-chain | pickle deserialization on model load |
| [ntlm-relay-corp](../modules/ntlm-relay-corp/manifest.yaml) | broadcast-cred-harvest | NetNTLMv2 responder/relay |
| [bmc-super](../modules/bmc-super/manifest.yaml) | oob-management | firmware signature bypass + SMASH input |

Each module ships a `vulnerability.cves` list and a `vulnerability.source`
URL — real CVEs plus the public advisory the manifest grounds against. That
is the input shape `patch-diff-poc` consumes: a commit URL discoverable from
the advisory, and a target the operator is explicitly scoped to.

## Verification

The patch-diff workflow and the expansion each have their own test file.
Nothing in this document is unverified:

```
# EvilKit side (23 tests over the recipe, renderer, scope gate)
cd ~/evilkit && python3 -m pytest tests/test_patch_diff_poc.py -q

# Keystone side (expansion graph, CVE grounding, evidence shape)
python3 -m unittest tests.test_expansion -v
```

Both suites are green at the time of this writing and run from stock Python 3.
