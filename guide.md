# cyber-lab — Guide

> **Version 0.7.** Eight chapters, each end to end and *proven on real VMs*
> (`qlab test cyber-lab` → 46 checks green): the ban is the proof; close a
> vulnerable PHP app; the blind filter; the Docker/FORWARD trap; the mail that
> lies (SPF); DMARC says reject; the service that obeys (raw TCP); and the mail
> that proves itself (DKIM signing — the send side).

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

## Chapter 4 — the firewall that wasn't (Docker/FORWARD)

The defender runs a container that publishes a port (`:8888`). You raise ufw and
deny that port. ufw says active, the rule is there. And the attacker still gets
in:

```
# defender
sudo ufw allow 22/tcp; sudo ufw allow 8080/tcp
sudo ufw deny 8888/tcp; sudo ufw --force enable
sudo ufw status                                   # active, 8888 DENY
# attacker
curl http://192.168.100.1:8888                    # 200 — STILL reachable
```

Why: a published port is DNAT'd in `nat/PREROUTING` and then **FORWARDED** to the
container — it never passes through `INPUT`, which is where ufw writes its rules.
The fix has to live where the traffic actually is, the `DOCKER-USER` chain of
FORWARD. And a subtlety that is itself the lesson: by the time a packet reaches
`DOCKER-USER`, the DNAT has already rewritten its destination port to the
container's (`80`), so you must match the *original* port via conntrack:

```
# defender
sudo docker-forward-fix        # iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8888 -j DROP
# attacker
curl http://192.168.100.1:8888 # now blocked
```

ufw was "active" the entire time. "Active" was never the question. (This is the
2026-08-19 VPS lesson, exactly: ufw does not protect ports published by Docker.)

## Chapter 5 — the mail that lies (SPF, with DMARC published)

The defender runs a real Postfix, and a local DNS that serves the records the
anti-spoofing checks read. The spoofable domain `boss.lab` publishes an SPF
record that authorises exactly one address — not the attacker — and ends in
`-all`; its `_dmarc.boss.lab` says `p=reject`. So a mail *claiming* to come from
`boss.lab` is a checkable claim.

From the attacker, send it — first while the defender is undefended, then after:

```
# defender — undefended
sudo mail-spf-off
# attacker
spoof-mail ceo@boss.lab victim@mail.lab 192.168.100.1     # accepted (250)

# defender — enforce SPF
sudo mail-spf-on
# attacker
spoof-mail ceo@boss.lab victim@mail.lab 192.168.100.1     # rejected:
#   550 5.7.23 ... SPF fail - not authorized ... ip=192.168.100.2
```

Same forged mail, two answers — because the difference was never "is Postfix
running", it was whether the claim was checked.

**Scope of this chapter.** What is enforced here is **SPF** (via
`postfix-policyd-spf`): the sender's IP is checked against the domain's SPF
record, and a `Fail` is rejected at SMTP time. The DMARC layer that ties SPF and
DKIM together is the next chapter.

## Chapter 6 — DMARC says reject

SPF caught the spoof by the sender's IP. DMARC catches it for the fuller reason,
and on its own. The domain publishes `_dmarc.boss.lab TXT "v=DMARC1; p=reject"`,
and the defender runs two milters: **opendkim** (verifies any DKIM signature) and
**opendmarc** (computes SPF itself, reads the DKIM result, checks both for
*alignment* with the `From:` domain, and rejects on failure when the policy says
so).

To show it is DMARC doing the work — not the SPF policy from chapter 5 — turn the
SPF policy off and let the milters stand alone:

```
# defender
sudo mail-spf-off        # chapter 5's SPF policy off
sudo mail-dmarc-off      # milters off → undefended
# attacker
spoof-mail ceo@boss.lab victim@mail.lab 192.168.100.1   # accepted (250)

# defender
sudo mail-dmarc-on       # opendkim + opendmarc in the milter chain
# attacker
spoof-mail ceo@boss.lab victim@mail.lab 192.168.100.1   # rejected:
#   550 5.7.1 rejected by DMARC policy for boss.lab
```

The forged mail fails SPF (wrong IP) and carries no DKIM signature aligned to
`boss.lab`, so DMARC fails, and `p=reject` is honoured at the milter. Same forged
mail as chapter 5, rejected for the reason DMARC exists.

## Chapter 7 — the service that obeys (raw TCP)

Not every hole is HTTP. The defender runs a hand-rolled TCP service on `:9000`
(ported from the old cybersecurity-lab) that runs whatever you send and reads
whatever path you name:

```
# attacker
printf 'exec id\nquit\n'          | nc 192.168.100.1 9000   # RCE: uid=0(root)
printf 'file /etc/passwd\nquit\n' | nc 192.168.100.1 9000   # traversal
```

Then the same close-it-and-prove-it loop:

```
# defender
sudo touch /etc/cyber-lab/tcp-hardened
sudo systemctl restart cyber-tcp
# attacker — the same commands are now refused
printf 'exec id\nquit\n' | nc 192.168.100.1 9000            # refused
```

The point beyond the exploit: a filter or WAF tuned to HTTP would never see this
traffic at all. The protocol is the attacker's, not the web's.

## Chapter 8 — the mail that proves itself (DKIM signing)

The send side, and the last leg of the mail story. Chapters 5–6 rejected a spoof
because the claim to be `boss.lab` was checkable and false. This one is the
mirror: our own `mail.lab` **signs** what it sends, so a receiver can check the
claim to be us and find it *true*. The defender generates a DKIM key, publishes
the public half at `mail._domainkey.mail.lab`, and opendkim signs outbound mail:

```
# defender — send a real message through Postfix from a mail.lab sender
swaks --server 127.0.0.1 --from postmaster@mail.lab --to victim@mail.lab
# the delivered message now carries:
#   DKIM-Signature: v=1; a=rsa-sha256; d=mail.lab; s=mail; ...
# and it verifies against the published key:
sudo sed '1{/^From /d}' /var/mail/victim | dkimverify      # signature ok
```

Two facts made this work, both found on a real boot: opendkim must run as its own
user (a key dir owned by `opendkim` is refused when it runs as root), and its
`InternalHosts` must be a file that lists `localhost` explicitly — with an inline
list it treated `localhost` as external and signed nothing.

## Where this goes next

The plugin covers its eight backend chapters — the whole SPF/DKIM/DMARC story
now closed, both receive and send sides. What remains is the browser sibling
**EDU-CYBER** (browser-friendly chapters, two hosts in one v86 kernel, using
these proven invariants as reference).
