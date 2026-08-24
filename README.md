# cyber-lab — Attack / Defense (the attack IS the test)

[![QLab Plugin](https://img.shields.io/badge/QLab-Plugin-blue)](https://github.com/manzolo/qlab)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-0.1%20first%20slice-orange)]()

A [QLab](https://github.com/manzolo/qlab) plugin that boots two VMs on a private
internal LAN — an **attacker** and a **defender** — to learn how to defend, and
to *prove* a defense works instead of assuming it does.

| VM | Internal IP | Packages | Role |
|----|-------------|----------|------|
| `cyber-lab-defender` | `192.168.100.1` | `fail2ban`, `iptables`, `ufw`, `docker.io`, `php-cli`, `postfix` + a vulnerable web app + local DNS | the machine you harden |
| `cyber-lab-attacker` | `192.168.100.2` | `nmap`, `netcat-openbsd`, `curl`, `swaks` + `burst-ssh`, `spoof-mail` | the machine you attack from |

## The thesis

A running service is not a working defense. In this lab **the attack is the
test**: every exercise is checked by firing the real attack from the attacker
and measuring the effect on the defender — never by reading `systemctl status`.

## Quick start

```bash
qlab install cyber-lab      # from the registry, or: qlab install <git-url>
qlab run cyber-lab          # boots both VMs (~90s)
qlab test cyber-lab         # fires the attack and proves the ban is real
```

By hand, the loop that is the whole point:

```bash
# attacker
nc -w3 -z 192.168.100.1 22        # OPEN — the door is open to you
burst-ssh 192.168.100.1 8         # the attack: 8 failed logins
# defender
sudo fail2ban-client status sshd  # 192.168.100.2 is now banned
# attacker
nc -w3 -z 192.168.100.1 22        # BLOCKED — the ban is effective
```

Full walkthrough in [`guide.md`](guide.md).

## Why an internal LAN and not port-forwarding

Through the host's port-forwarding the defender would see every connection
coming from the gateway, and fail2ban would ban the gateway. On the internal L2
segment the source is the attacker's real IP — which is what makes "the ban is
the proof" a measurable fact. (Skeleton borrowed from `firewall-lab`; the
internal socket LAN from `mail-lab`.)

## Chapters (all proven on real VMs — `qlab test` → 22 checks green)

1. **The ban is the proof** — a burst of failed logins gets the attacker's real
   IP banned in the register AND locked out at the packet level.
2. **Close it, and prove it closed** — a vulnerable PHP app (RCE, XSS, path
   traversal); exploit it, harden it, then watch the same attacks get refused.
3. **The zero has two readings** — the blind filter: the same log read by a
   broken filter (0 matches, looks calm) and a correct one (matches everything).
4. **The firewall that wasn't** — the Docker/FORWARD trap: ufw active and denying
   a port, yet the attacker still reaches it (published-port traffic is FORWARDed,
   not INPUT); the fix is a conntrack DROP in DOCKER-USER.
5. **The mail that lies** — a spoofed sender: forged `From: boss.lab` accepted
   while undefended, rejected (550, SPF fail) once SPF is enforced. DMARC record
   published (p=reject); enforcement here is SPF (opendmarc/DKIM is the next layer).

## Status

**0.4.** Five chapters, each end to end with an automated invariant, all green
on a real boot (31 checks). Planned next: DKIM signing + opendmarc for a full
DMARC verdict, and the EDU-CYBER browser sibling.

> ⚠️ This is teaching material for an **isolated** lab. Nothing here is meant to
> be pointed at anything outside its own private LAN.
