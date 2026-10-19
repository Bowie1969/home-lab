# Fork & Knife — the ghost-kitchen supply-chain range

Target: **Fork & Knife (FK)** — a ghost-kitchen SaaS running a billing
platform. The red objective is a **software supply-chain attack with
second-order / delayed execution**: the attacker never touches the runner
directly; they poison a *build job* through the CI webhook, and the poison is
only executed when the CI runner ticks on its timer and drains the queue.

This is the "fork-and-knife" estate: the fork is the developer pipeline the
attacker reaches through the public portal, the knife is the CI runner whose
deploy credentials get cut loose into build results.

## Estate (10.60.0.0/24, VLAN 60)

| ip | host | role |
|----|------|------|
| 10.60.0.10 | fk-devportal | public developer/status web app + git mirror (HTTP) |
| 10.60.0.11 | fk-webhook | CI webhook, accepts pushed build jobs and queues them (HTTP) |
| 10.60.0.12 | fk-runner | automated runner, ticks on a timer and executes queued jobs |
| 10.60.0.13 | fk-vault | prod billing vault, crown (HTTP) |

Attacker reaches `fk-devportal` and `fk-webhook` from outside; the runner and
the vault are only reachable through the chain (the deploy token is the key to
the vault).

## The delayed chain (one authored exploit, every step proven)

1. **Leak from history** — `fk-devportal` serves the git mirror at
   `GET /repo/log`. The commit history leaks **two** credentials, both readable
   with a plain HTTP GET and no external tools:
   - the **junior dev CI token** (`DEV_TOKEN`), committed in a WIP commit;
   - the **weak webhook secret** (`WEBHOOK_SECRET`), committed in the
     webhook-wiring commit and explicitly flagged "rotate this secret".
2. **Push a poisoned job** — `POST /push` on `fk-webhook`. The request must
   carry the weak secret in `X-Webhook-Secret` and identify the author with the
   junior dev token in `author_token`. The job body is arbitrary JSON; its
   `command` field is attacker-controlled and is *queued, not run*.
3. **Delayed execution** — `fk-runner` runs a timer loop (tick ~0.25s) that
   drains the queue and executes each job's `command` via a subprocess. The
   attacker does **not** touch the runner directly: execution happens only when
   the tick fires (second-order execution).
4. **Recover the deploy token** — for every job the runner drops its output
   into `results/<author_token>/<job_id>/`, and — the misconfiguration — also
   drops the **SSH deploy token** into `deploy-token.txt` alongside it, in a
   directory the job author (who knows the author token) can read.
5. **Crown** — present the SSH deploy token as a bearer token to the prod
   billing vault (`POST /settle` on `fk-vault`). It returns
   `KEYSTONE{forkknife-crown-<rot>}` for the current rotation.

The poison is arbitrary code execution on the CI runner; the crown is the
deploy token the runner hands back in results, which unlocks prod billing.

## Why this estate

- **Second-order / delayed** is real: the webhook only *queues*, and the runner
  only *executes on a timer*. The test waits by polling the results directory
  and never calls the runner process, so the delay is part of the proof.
- The two leaks are both *necessary*: the weak secret authenticates the push,
  and the junior dev token authorises the job and names the results directory.
- Pure Python 3 stdlib services on ephemeral localhost ports — no podman,
  libvirt or qemu needed to prove the chain.

## Build order

1. `services.py` — dev portal, webhook, runner, vault (stdlib, ephemeral ports).
2. `range/tests/test_estate_fork_and_knife.py` — drives the chain end-to-end
   and asserts every step.
3. SD-card tooling (unchanged): `keystone/sdcard.py`, `bin/packcard.sh`,
   `bin/loadcard.sh`.
