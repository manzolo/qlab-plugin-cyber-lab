# cyber-lab — Guide

> **Version 0.1 — first vertical slice.** One chapter, but end to end and
> *proven*: the attack, the ban, and the two ways the ban is a fact rather than
> a hope. More chapters (vulnerable PHP, mail spoofing + SPF/DKIM/DMARC, the
> Docker/FORWARD trap) are planned — this one carries the method the rest reuse.

## The one idea

A running service is **not** a working defense. `systemctl is-active fail2ban`
being green tells you a daemon is up — nothing about whether it stops anyone.
The proof of a defense is elsewhere: a **ban in the register**, keyed to the
attacker's real address, and the attacker **actually locked out** afterwards.

So in this lab **the attack is the test.** Every exercise is verified by firing
the real attack from the attacker VM and then measuring the effect on the
defender — never by reading a config file or a unit's status.

## Why two machines on a private LAN

The attacker (`192.168.100.2`) and the defender (`192.168.100.1`) sit on a
direct internal L2 segment. That detail is the lab: on it, the defender's sshd
sees connections coming **from the attacker's real IP**, so fail2ban can ban
*that*. If the two talked through the host's port-forwarding instead (as a
simpler lab would), every connection would appear to come from the gateway, and
fail2ban would ban the gateway — a green light in front of an open door.

## Chapter 1 — the raffica and the ban

Boot the lab and wait ~90s (`qlab run cyber-lab`). Then, by hand:

1. **The door is open — to you.** On the attacker:
   ```
   nc -w3 -z 192.168.100.1 22 && echo OPEN
   ```
2. **Nobody is banned yet.** On the defender:
   ```
   sudo fail2ban-client status sshd
   ```
   The "Banned IP list" is empty. Hold onto that zero — see below.
3. **Attack.** On the attacker, knock eight times with the wrong key:
   ```
   burst-ssh 192.168.100.1 8
   ```
   Each attempt is a failed login the defender's sshd writes to its journal,
   and that fail2ban's `sshd` filter counts.
4. **The ban — proof #1.** On the defender, again:
   ```
   sudo fail2ban-client status sshd
   ```
   Now `192.168.100.2` is in the banned list. And look at the mechanism:
   ```
   sudo iptables -L -n -v | grep 192.168.100.2
   ```
   There is a real DROP rule doing the work.
5. **The lockout — proof #2.** Back on the attacker, repeat step 1:
   ```
   nc -w3 -z 192.168.100.1 22 && echo OPEN || echo BLOCKED
   ```
   It now says BLOCKED. The ban is not just *recorded*, it is *effective*.

Prove all of that automatically at any time:
```
qlab test cyber-lab
```

## The zero has two readings

That empty banned list in step 2 is the trap this whole collection is built to
teach. A zero has two opposite meanings:

- **"nobody has attacked yet"** — the honest baseline, or
- **"the filter is blind"** — fail2ban is running, but its regex never matches
  the log lines, so it would count zero *even under attack*.

You cannot tell them apart by staring at the number. You separate them by
**doing the attack and watching the zero move** — exactly steps 3–4. A defense
you have never seen react is not a defense you have verified. (This bit is not
abstract: on a real server, a fail2ban filter once matched **0 of 13,474** log
lines because it stripped the date before applying its pattern. It looked calm.
It was blind.)

## Where this goes next

The same shape — attack from one VM, measure the invariant on the other —
carries the planned chapters: vulnerable PHP (exploit it, close it, prove the
exploit now fails), a mail server (send a spoofed sender, prove SPF/DKIM/DMARC
reject it), and the Docker/FORWARD trap (firewall "on", port still reachable).
