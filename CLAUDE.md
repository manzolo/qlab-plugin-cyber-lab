# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A QLab plugin that boots two VMs on a private internal LAN — an **attacker** and
a **defender** — for attack/defense exercises. Its thesis: a running service is
not a working defense; **the attack is the test**. Every exercise is verified by
firing the real attack from the attacker VM and measuring the effect on the
defender (a ban in the register, the attacker locked out) — never by reading
`systemctl status`.

## Architecture

Two VMs on internal LAN `192.168.100.0/24`:
1. **cyber-lab-defender** (`192.168.100.1`) — the machine you harden: sshd on the
   LAN, fail2ban + iptables.
2. **cyber-lab-attacker** (`192.168.100.2`) — the machine you attack from: nmap,
   netcat, and a `burst-ssh` helper.

The internal LAN is a QEMU socket-multicast segment (borrowed from mail-lab),
NOT host port-forwarding (as firewall-lab uses). This is deliberate: only on a
real L2 segment does the defender see the attacker's real source IP, which is
what makes "the ban is the proof" a measurable fact instead of banning the
gateway.

## Key files

- `plugin.conf` — metadata (name, version, description)
- `install.sh` — dependency check
- `run.sh` — downloads the Ubuntu cloud image, writes cloud-init for both VMs
  (static internal IPs matched by MAC), boots them on the shared socket LAN
- `guide.md` — the lessons
- `tests/` — `qlab test` entry point (`run_all.sh`) + one file per invariant

## Testing rule

An invariant asserts an effect, never a config. Assert the ban exists AND the
attacker is locked out — never `systemctl is-active`. A green must be reproduced
on a real boot before it is trusted: writing a check is not verifying it.
