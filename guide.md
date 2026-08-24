# cyber-lab — Guide

> **Version 0.2.** Three chapters, each end to end and *proven on real VMs*
> (`qlab test cyber-lab` → 22 checks green): the ban is the proof; close a
> vulnerable PHP app and prove it closed; and the blind filter (a zero that
> lies). Still planned: mail spoofing + SPF/DKIM/DMARC and the Docker/FORWARD
> trap — both on real services, both verified the same way.

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

## Chapter 2 — close it, and prove it closed (vulnerable PHP)

The defender runs a small PHP app on `http://192.168.100.1:8080` with the three
classic web holes behind one script — and a switch that hardens all of them.

1. **Exploit it.** From the attacker, run a command *on the server*:
   ```
   curl 'http://192.168.100.1:8080/?r=exec&cmd=id'      # RCE: prints uid=…
   curl 'http://192.168.100.1:8080/?r=echo&msg=<script>x</script>'   # XSS
   curl 'http://192.168.100.1:8080/?r=file&name=/etc/passwd'         # traversal
   ```
2. **Close it.** On the defender, flip the app to its hardened path and restart:
   ```
   sudo touch /etc/cyber-lab/web-hardened
   sudo systemctl restart cyber-web
   ```
3. **Prove it.** Re-run the *same* attacks from the attacker: the RCE and the
   traversal now answer `403`, and the XSS payload comes back escaped. "I added
   a check" was not a defense until the attack that worked stopped working.

## Chapter 3 — the zero has two readings (the blind filter)

A fail2ban counter at zero means either "nobody attacked" or "the filter is
blind" — and you cannot tell which by looking. On the defender, the same 5-line
sample log is read by two filters:

```
sudo fail2ban-regex /opt/cyber-lab/samples/auth-sample.log /etc/fail2ban/filter.d/cyber-blind.conf
sudo fail2ban-regex /opt/cyber-lab/samples/auth-sample.log /etc/fail2ban/filter.d/cyber-good.conf
```

The blind filter matches **0**; the good one matches **5** — same log, same
events. The blind filter's regex starts with a date, but fail2ban strips the
date from every line *before* applying `failregex`, so it can never match. The
events were always there; the zero was the filter's fault. (On a real server
this exact mistake once produced 0 matches on 13,474 lines — it looked calm, it
was blind.)

## Where this goes next

The same shape — attack from one VM, measure the invariant on the other — is
what the remaining chapters need: a mail server (send a spoofed sender, prove
SPF/DKIM/DMARC reject it) and the Docker/FORWARD trap (firewall "on", port still
reachable). Both are real services on the defender, verified the same way.
