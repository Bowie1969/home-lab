#!/usr/bin/env python3
"""CI runner agent for the runner-escape module.

The runner is the pivot box of the DMZ tier: any foothold from another module
lets an operator drop a job file here; jobs are executed as root by design
(technique_class container-escape). The container also carries a planted
"host" filesystem at /hostfs, modelling a CI runner started with an
over-mounted host path: writing through /hostfs lands "outside" the runner
rootfs, and /hostfs/root/flag.txt is the escape prize. stdlib only.
"""
import os
import subprocess
import time

JOBS_DIR = "/jobs"
os.makedirs(JOBS_DIR, exist_ok=True)


def run_job(path):
    out_path = path[:-len(".job")] + ".out"
    try:
        result = subprocess.run(["/bin/sh", path], capture_output=True,
                                timeout=30, text=True)
        output = result.stdout + result.stderr
    except Exception as exc:
        output = "job failed: %s" % exc
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(output)
    os.remove(path)
    print("runner: executed %s -> %s" % (os.path.basename(path),
                                         os.path.basename(out_path)),
          flush=True)


def main():
    print("runner: waiting for jobs in %s" % JOBS_DIR, flush=True)
    while True:
        try:
            for name in sorted(os.listdir(JOBS_DIR)):
                if name.endswith(".job"):
                    run_job(os.path.join(JOBS_DIR, name))
        except Exception as exc:
            print("runner: %s" % exc, flush=True)
        time.sleep(2)


if __name__ == "__main__":
    main()
