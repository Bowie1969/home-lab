# SSH tunnel exercise contract

`ssh-weak` is a DMZ SSH bastion. Its intentionally weak `deploy` account is an
initial-access exercise. After a foothold, the operator must author an executable
shell script on the operator host which brings up and tears down a local SSH port
forward through this bastion to a CORP host. The range deliberately provides no
tunnel wrapper, aliases, keys, or preconfigured SSH host entries to the operator.

The script must use OpenSSH local forwarding (`ssh -N -L`) to `ssh-weak`. It must
bind the local listener to loopback, use `ExitOnForwardFailure=yes`, retain an
unambiguous PID or control socket for shutdown, and take destination host, remote
port and local port as parameters. It must not request global/reverse forwarding,
`GatewayPorts`, `PermitTunnel`, or connect outside 10.80.0.0/16.

The intended live path is:

```
operator -> ssh-weak (DMZ SSH) -> target in CORP
```

The current CORP VMs are not provisioned. When they are ready, use their assigned
addresses from `build/vms.json`; during harness verification a temporary listener
at `10.80.20.250:8200` proves the same forwarding path.

For a run to claim tunnel-pivot evidence, collect all of the following:

- `fsdiff.json`: the executable operator-authored tunnel script was added or
  modified on `attacker`.
- pcap: SSH traffic from attacker to `10.80.10.30:22`, followed by traffic from
  `10.80.10.30` to the CORP target.
- journal: a `pivot` event naming `ssh-weak` as the relay and the CORP target.

This is an exercise requirement rather than a claim that remote SSH can identify
the local process that invoked it. The scorer stays path-agnostic; the evidence
records the actual tunnel and operator artifact for review.
