#!/usr/bin/env bash
# cyber-lab run script — boots two VMs on a private internal LAN for
# attack/defense exercises. Skeleton borrowed from firewall-lab; the internal
# socket LAN (so the defender sees the attacker's REAL IP) borrowed from mail-lab.

set -euo pipefail

PLUGIN_NAME="cyber-lab"
DEFENDER_VM="cyber-lab-defender"
ATTACKER_VM="cyber-lab-attacker"

# Internal LAN — direct VM-to-VM link via QEMU socket multicast.
# WHY this and not hostfwd (as firewall-lab does): through hostfwd/SLIRP the
# defender would see every connection coming from the gateway (10.0.2.2), not
# from the attacker. fail2ban would then ban the gateway — useless. On a real
# L2 segment the source IP is the attacker's, so "the ban is the proof" becomes
# a measurable fact. The mcast address and MAC prefix (0C) are chosen not to
# collide with mail-lab (07) if both labs run at once.
INTERNAL_MCAST="230.0.0.12:10212"
DEFENDER_INTERNAL_IP="192.168.100.1"
ATTACKER_INTERNAL_IP="192.168.100.2"
DEFENDER_LAN_MAC="52:54:00:00:0c:01"
ATTACKER_LAN_MAC="52:54:00:00:0c:02"

echo "============================================="
echo "  cyber-lab: Attack / Defense (the attack IS the test)"
echo "============================================="
echo ""
echo "  Two VMs on an internal LAN (192.168.100.0/24):"
echo ""
echo "    1. $DEFENDER_VM  ($DEFENDER_INTERNAL_IP)"
echo "       The machine you harden: sshd on the LAN, fail2ban + iptables."
echo ""
echo "    2. $ATTACKER_VM  ($ATTACKER_INTERNAL_IP)"
echo "       The machine you attack from: nmap, netcat, burst-ssh."
echo ""

# Source QLab core libraries
if [[ -z "${QLAB_ROOT:-}" ]]; then
    echo "ERROR: QLAB_ROOT not set. Run this plugin via 'qlab run ${PLUGIN_NAME}'."
    exit 1
fi

for lib_file in "$QLAB_ROOT"/lib/*.bash; do
    # shellcheck source=/dev/null
    [[ -f "$lib_file" ]] && source "$lib_file"
done

# Configuration
WORKSPACE_DIR="${WORKSPACE_DIR:-.qlab}"
LAB_DIR="lab"
IMAGE_DIR="$WORKSPACE_DIR/images"
CLOUD_IMAGE_URL=$(get_config CLOUD_IMAGE_URL "https://cloud-images.ubuntu.com/minimal/releases/jammy/release/ubuntu-22.04-minimal-cloudimg-amd64.img")
CLOUD_IMAGE_FILE="$IMAGE_DIR/ubuntu-22.04-minimal-cloudimg-amd64.img"
MEMORY="${QLAB_MEMORY:-$(get_config DEFAULT_MEMORY 1024)}"

mkdir -p "$LAB_DIR" "$IMAGE_DIR"

# =============================================
# Step 1: Cloud image (shared by both VMs)
# =============================================
info "Step 1: Cloud image"
if [[ -f "$CLOUD_IMAGE_FILE" ]]; then
    success "Cloud image already downloaded: $CLOUD_IMAGE_FILE"
else
    echo ""
    info "Downloading Ubuntu cloud image..."
    echo "  URL: $CLOUD_IMAGE_URL"
    echo ""
    check_dependency curl || exit 1
    curl -L -o "$CLOUD_IMAGE_FILE" "$CLOUD_IMAGE_URL" || {
        error "Failed to download cloud image."
        exit 1
    }
    success "Cloud image downloaded: $CLOUD_IMAGE_FILE"
fi
echo ""

# =============================================
# Step 2: Cloud-init configurations
# =============================================
info "Step 2: Cloud-init configuration for both VMs"
echo ""

# --- Defender VM cloud-init ---
info "Creating cloud-init for $DEFENDER_VM..."

cat > "$LAB_DIR/user-data-defender" <<'USERDATA'
#cloud-config
hostname: cyber-lab-defender
users:
  - name: labuser
    plain_text_passwd: labpass
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - "__QLAB_SSH_PUB_KEY__"
ssh_pwauth: true
package_update: true
packages:
  - fail2ban
  - iptables
  - ufw
  - docker.io
  - python3-systemd
  - php-cli
  - postfix
  - postfix-policyd-spf-python
  - opendkim
  - opendkim-tools
  - opendmarc
  - dnsmasq
  - net-tools
  - vim
  - nano
write_files:
  # Static IP on the internal LAN NIC, matched by MAC (the SLIRP NIC keeps DHCP
  # via the default 50-cloud-init.yaml, so 'qlab shell' still works).
  - path: /etc/netplan/60-internal.yaml
    permissions: '0600'
    content: |
      network:
        version: 2
        ethernets:
          cyberlan:
            match:
              macaddress: "52:54:00:00:0c:01"
            addresses:
              - 192.168.100.1/24
  # The jail. Short times so the exercise resolves in seconds, not minutes.
  # NOTE what is NOT here: ignoreip does not list 192.168.100.0/24 — if it did,
  # the attacker would be whitelisted and the lab would teach a false green.
  - path: /etc/fail2ban/jail.d/cyber-lab.local
    content: |
      [DEFAULT]
      ignoreip = 127.0.0.1/8 ::1
      bantime  = 300
      findtime = 120
      maxretry = 3

      [sshd]
      enabled  = true
      backend  = systemd
  # --- Vulnerable PHP web app (chapters 8-10) -------------------------------
  # Three classics behind one script, with a hardening switch: create the file
  # /etc/cyber-lab/web-hardened and restart cyber-web to flip every endpoint
  # from vulnerable to safe. The lab's loop is: exploit it, harden it, prove
  # the same exploit now fails.
  - path: /srv/web/index.php
    content: |
      <?php
      $hardened = file_exists('/etc/cyber-lab/web-hardened');
      $r = $_GET['r'] ?? 'home';
      // Every request is logged with a date and the client IP — raw material
      // for the "blind filter" chapter.
      $line = date('Y-m-d H:i:s')." request r=".$r." from ".($_SERVER['REMOTE_ADDR'] ?? '?')."\n";
      @file_put_contents('/var/log/cyber-web/access.log', $line, FILE_APPEND);
      if ($r === 'exec') {              // Remote Code Execution
        if ($hardened) { http_response_code(403); echo "refused: input is not executed\n"; }
        else { system($_GET['cmd'] ?? 'true'); }
      } elseif ($r === 'echo') {        // Cross-Site Scripting
        $msg = $_GET['msg'] ?? '';
        echo "Hello ".($hardened ? htmlspecialchars($msg) : $msg)."\n";
      } elseif ($r === 'file') {        // Path traversal
        $name = $_GET['name'] ?? '';
        if ($hardened) {
          $pp = realpath('/srv/web/'.basename($name));
          if ($pp && str_starts_with($pp, '/srv/web/')) { readfile($pp); }
          else { http_response_code(403); echo "refused: outside web root\n"; }
        } else { readfile($name); }
      } else {
        echo "cyber-lab web — try ?r=echo&msg=, ?r=file&name=, ?r=exec&cmd=\n";
        echo $hardened ? "state: HARDENED\n" : "state: VULNERABLE\n";
      }
  - path: /etc/systemd/system/cyber-web.service
    content: |
      [Unit]
      Description=cyber-lab vulnerable PHP web app
      After=network-online.target
      [Service]
      ExecStartPre=/bin/mkdir -p /var/log/cyber-web
      ExecStart=/usr/bin/php -S 0.0.0.0:8080 -t /srv/web
      Restart=always
      [Install]
      WantedBy=multi-user.target
  # --- The blind filter (chapter 7) -----------------------------------------
  # A sample auth log, plus two filters for the same events. The broken one
  # includes a date at the start of its regex — but fail2ban strips the date
  # from each line BEFORE applying failregex, so it matches nothing and looks
  # calm under attack. The good one drops the date and matches. This is the
  # 2026-08-19 VPS incident in miniature: 0 of 13,474 lines, because the date
  # was in the way.
  - path: /opt/cyber-lab/samples/auth-sample.log
    content: |
      2026-08-19 10:00:01 sshd[111]: Failed password for invalid user admin from 192.168.100.2 port 5001 ssh2
      2026-08-19 10:00:02 sshd[112]: Failed password for invalid user root from 192.168.100.2 port 5002 ssh2
      2026-08-19 10:00:03 sshd[113]: Failed password for invalid user test from 192.168.100.2 port 5003 ssh2
      2026-08-19 10:00:04 sshd[114]: Failed password for invalid user oracle from 192.168.100.2 port 5004 ssh2
      2026-08-19 10:00:05 sshd[115]: Failed password for invalid user git from 192.168.100.2 port 5005 ssh2
  - path: /etc/fail2ban/filter.d/cyber-blind.conf
    content: |
      # BROKEN ON PURPOSE. fail2ban removes the leading date before matching,
      # so a failregex that starts with a date can never match a single line.
      [Definition]
      failregex = ^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d sshd\[\d+\]: Failed password for .* from <HOST>
      ignoreregex =
  - path: /etc/fail2ban/filter.d/cyber-good.conf
    content: |
      # The same intent, without the date the framework already stripped.
      [Definition]
      failregex = sshd\[\d+\]: Failed password for .* from <HOST>
      ignoreregex =
  # --- The Docker/FORWARD trap (chapter 4) ----------------------------------
  # Docker publishes a port by writing rules in nat/PREROUTING (DNAT) and the
  # DOCKER chain of FORWARD. ufw writes rules in INPUT. Traffic to a published
  # port is DNAT'd and FORWARDED — it never touches INPUT — so 'ufw deny 8888'
  # blocks nothing. The honest fix lives where the traffic actually is: a DROP
  # in DOCKER-USER, which iptables evaluates first inside FORWARD.
  - path: /usr/local/bin/docker-forward-fix
    permissions: '0755'
    content: |
      #!/bin/bash
      # Close the port ufw could not. Idempotent.
      #
      # Subtlety that IS the lesson: the DNAT for a published port happens in
      # nat/PREROUTING, BEFORE FORWARD. So by the time a packet reaches
      # DOCKER-USER its destination port is already the container's (80), not
      # 8888 — a plain "--dport 8888" here matches nothing. We match the
      # ORIGINAL destination port via conntrack instead.
      if iptables -C DOCKER-USER -p tcp -m conntrack --ctorigdstport 8888 -j DROP 2>/dev/null; then
        echo "already fixed: DOCKER-USER already drops original :8888"
      else
        iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8888 -j DROP
        echo "fixed: DOCKER-USER now drops traffic whose ORIGINAL port was 8888"
        echo "(on the FORWARD path, where the published-port traffic actually is)"
      fi
  - path: /usr/local/bin/docker-forward-unfix
    permissions: '0755'
    content: |
      #!/bin/bash
      iptables -D DOCKER-USER -p tcp -m conntrack --ctorigdstport 8888 -j DROP 2>/dev/null || true
      iptables -D DOCKER-USER -p tcp --dport 8888 -j DROP 2>/dev/null || true
      echo "DOCKER-USER rule removed"
  # --- Mail spoofing vs SPF/DMARC (chapter 5) -------------------------------
  # A local DNS (dnsmasq on 127.0.0.1) serves the records the SPF/DMARC checks
  # read. The spoofable domain boss.lab authorises ONE address that is NOT the
  # attacker, and ends in -all; its _dmarc says p=reject. So a mail claiming to
  # come from boss.lab, sent from the attacker's IP, fails SPF — and once the
  # policy is enforced, Postfix rejects it at SMTP time (550).
  - path: /etc/dnsmasq.d/cyber-lab.conf
    content: |
      listen-address=127.0.0.1
      bind-interfaces
      # unknown names go out via the SLIRP resolver, so the box still resolves
      server=10.0.2.3
      # the spoofable domain: only 10.9.9.9 may send, everyone else -> fail
      txt-record=boss.lab,"v=spf1 ip4:10.9.9.9 -all"
      txt-record=_dmarc.boss.lab,"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"
      address=/boss.lab/10.9.9.9
      # our own domain
      txt-record=mail.lab,"v=spf1 ip4:192.168.100.1 -all"
      address=/mail.lab/192.168.100.1
  - path: /usr/local/bin/mail-spf-on
    permissions: '0755'
    content: |
      #!/bin/bash
      # Enforce SPF: add the policy service to the recipient restrictions.
      postconf -e 'smtpd_recipient_restrictions=permit_mynetworks, reject_unauth_destination, check_policy_service unix:private/policyd-spf'
      systemctl reload postfix
      echo "SPF enforcement ON (forged senders that fail SPF are now rejected)"
  - path: /usr/local/bin/mail-spf-off
    permissions: '0755'
    content: |
      #!/bin/bash
      # Undefended: no SPF policy. A forged sender is accepted.
      postconf -e 'smtpd_recipient_restrictions=permit_mynetworks, reject_unauth_destination'
      systemctl reload postfix
      echo "SPF enforcement OFF (forged senders are accepted — the undefended state)"
  # --- DMARC (chapter 6): opendkim (verify) + opendmarc (enforce) -----------
  # opendmarc computes SPF itself (SPFSelfValidate) and reads DKIM results from
  # opendkim ahead of it in the milter chain, checks alignment against the From:
  # domain, and with RejectFailures rejects when the domain's _dmarc says
  # p=reject. inet sockets on localhost avoid the classic unix-socket/group
  # permission pain between the milters and Postfix.
  - path: /etc/opendkim.conf
    content: |
      Syslog                  yes
      UMask                   002
      Mode                    v
      Socket                  inet:8891@localhost
      PidFile                 /run/opendkim/opendkim.pid
      OversignHeaders         From
      AutoRestart             yes
      Canonicalization        relaxed/simple
  - path: /etc/opendmarc.conf
    content: |
      AuthservID              mail.lab
      Syslog                  true
      Socket                  inet:8893@localhost
      PidFile                 /run/opendmarc/opendmarc.pid
      RejectFailures          true
      SPFSelfValidate         true
      IgnoreAuthenticatedClients true
      RequiredHeaders         true
  - path: /usr/local/bin/mail-dmarc-on
    permissions: '0755'
    content: |
      #!/bin/bash
      # Enforce DMARC via the milter chain (opendkim then opendmarc).
      systemctl restart opendkim opendmarc
      postconf -e 'milter_protocol=6'
      postconf -e 'milter_default_action=accept'
      postconf -e 'smtpd_milters=inet:localhost:8891,inet:localhost:8893'
      postconf -e 'non_smtpd_milters='
      systemctl reload postfix
      echo "DMARC enforcement ON (opendkim+opendmarc; p=reject domains are rejected)"
  - path: /usr/local/bin/mail-dmarc-off
    permissions: '0755'
    content: |
      #!/bin/bash
      postconf -e 'smtpd_milters='
      systemctl reload postfix
      echo "DMARC enforcement OFF (no milters)"
  - path: /etc/motd.raw
    content: |
      \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
        \033[1;32mcyber-lab-defender\033[0m — \033[1mThe machine you harden\033[0m
      \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m

        \033[1;33mInternal IP:\033[0m 192.168.100.1   \033[1;33mAttacker:\033[0m 192.168.100.2

        \033[1;33mThe question this VM answers:\033[0m
          not "is fail2ban running?" but "did it ban the attacker,
          and is the attacker actually locked out?"

        \033[1;33mUseful commands:\033[0m
          \033[0;32msudo fail2ban-client status sshd\033[0m       who is banned right now
          \033[0;32msudo iptables -L -n -v\033[0m                 the DROP rule that does it
          \033[0;32msudo journalctl -u ssh -n 50\033[0m           what the server actually saw
          \033[0;32msudo fail2ban-regex <log> <filter>\033[0m     does the filter even match?

        \033[1;33mCredentials:\033[0m  \033[1;36mlabuser\033[0m / \033[1;36mlabpass\033[0m
      \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m

runcmd:
  - chmod -x /etc/update-motd.d/* 2>/dev/null || true
  - sed -i 's/^#\?PrintMotd.*/PrintMotd yes/' /etc/ssh/sshd_config
  - sed -i 's/^session.*pam_motd.*/# &/' /etc/pam.d/sshd
  - printf '%b\n' "$(cat /etc/motd.raw)" > /etc/motd
  - rm -f /etc/motd.raw
  - netplan apply
  - systemctl restart ssh
  - systemctl enable fail2ban
  - systemctl restart fail2ban
  - mkdir -p /var/log/cyber-web /etc/cyber-lab
  - systemctl daemon-reload
  - systemctl enable cyber-web
  - systemctl start cyber-web
  # Docker/FORWARD trap: a container publishing :8888. dockerd needs a moment;
  # the pull goes out over the SLIRP NIC. Retry so a slow mirror does not leave
  # the chapter without its container.
  - systemctl enable docker
  - systemctl start docker
  - bash -c 'for i in 1 2 3 4 5; do docker pull nginx:alpine && break || sleep 10; done'
  - bash -c 'docker rm -f trap-web 2>/dev/null; docker run -d --restart=always --name trap-web -p 8888:80 nginx:alpine || true'
  # --- Mail: local DNS, then Postfix + SPF policy service -------------------
  - systemctl enable dnsmasq
  - systemctl restart dnsmasq
  - bash -c 'rm -f /etc/resolv.conf; echo "nameserver 127.0.0.1" > /etc/resolv.conf'
  - postconf -e 'myhostname=mail.lab'
  - postconf -e 'mydomain=mail.lab'
  - postconf -e 'myorigin=$mydomain'
  - postconf -e 'inet_interfaces=all'
  - postconf -e 'inet_protocols=ipv4'
  - postconf -e 'mydestination=$myhostname, mail.lab, localhost.localdomain, localhost'
  - postconf -e 'mynetworks=127.0.0.0/8'
  - postconf -e 'policyd-spf_time_limit=3600'
  - bash -c 'grep -q "^policyd-spf " /etc/postfix/master.cf || printf "policyd-spf unix - n n - 0 spawn\n    user=policyd-spf argv=/usr/bin/policyd-spf\n" >> /etc/postfix/master.cf'
  - id victim 2>/dev/null || useradd -m -s /usr/sbin/nologin victim
  # DMARC milters: enabled as services, but NOT wired into Postfix at boot, so
  # chapter 5 (SPF) stays isolated. Chapter 6 wires them in with mail-dmarc-on.
  - mkdir -p /run/opendkim /run/opendmarc
  - chown opendkim:opendkim /run/opendkim 2>/dev/null || true
  - chown opendmarc:opendmarc /run/opendmarc 2>/dev/null || true
  - systemctl enable opendkim opendmarc || true
  - systemctl restart opendkim opendmarc || true
  # start defended on SPF; DMARC milters present but off
  - /usr/local/bin/mail-spf-on
  - /usr/local/bin/mail-dmarc-off
  - systemctl enable postfix
  - systemctl restart postfix
  - echo "=== cyber-lab-defender VM is ready! ==="
USERDATA

sed -i "s|__QLAB_SSH_PUB_KEY__|${QLAB_SSH_PUB_KEY:-}|g" "$LAB_DIR/user-data-defender"

cat > "$LAB_DIR/meta-data-defender" <<METADATA
instance-id: ${DEFENDER_VM}-001
local-hostname: ${DEFENDER_VM}
METADATA

success "Created cloud-init for $DEFENDER_VM"

# --- Attacker VM cloud-init ---
info "Creating cloud-init for $ATTACKER_VM..."

cat > "$LAB_DIR/user-data-attacker" <<'USERDATA'
#cloud-config
hostname: cyber-lab-attacker
users:
  - name: labuser
    plain_text_passwd: labpass
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - "__QLAB_SSH_PUB_KEY__"
ssh_pwauth: true
package_update: true
packages:
  - nmap
  - netcat-openbsd
  - curl
  - swaks
  - net-tools
  - iputils-ping
  - vim
  - nano
write_files:
  - path: /etc/netplan/60-internal.yaml
    permissions: '0600'
    content: |
      network:
        version: 2
        ethernets:
          cyberlan:
            match:
              macaddress: "52:54:00:00:0c:02"
            addresses:
              - 192.168.100.2/24
  # The attack, packaged. A burst of invalid-user SSH attempts against the
  # defender — each one a failed auth the defender's sshd logs, and that
  # fail2ban's sshd filter counts. BatchMode=yes means no hanging password
  # prompt: each attempt fails immediately and cleanly.
  - path: /usr/local/bin/burst-ssh
    permissions: '0755'
    content: |
      #!/bin/bash
      # Usage: burst-ssh [target-ip] [count]
      target="${1:-192.168.100.1}"
      count="${2:-6}"
      echo "Firing $count failed SSH logins at $target ..."
      for i in $(seq 1 "$count"); do
        # timeout 8 is not cosmetic: a cold or wedged connection could otherwise
        # hang the whole burst for minutes (found the hard way on a real boot).
        # GSSAPIAuthentication=no skips a negotiation step that is pure latency
        # on an isolated LAN with no ticket infrastructure.
        timeout 8 ssh -o BatchMode=yes -o ConnectTimeout=4 \
            -o GSSAPIAuthentication=no \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=password -o PubkeyAuthentication=no \
            "intruder_${i}@${target}" true 2>/dev/null || true
        echo "  attempt $i sent"
      done
      echo "Done. Now go to the defender and ask: did it get banned?"
  - path: /usr/local/bin/spoof-mail
    permissions: '0755'
    content: |
      #!/bin/bash
      # Send a mail with a FORGED sender. Usage: spoof-mail [from] [to] [server]
      from="${1:-ceo@boss.lab}"
      to="${2:-victim@mail.lab}"
      server="${3:-192.168.100.1}"
      echo "Pretending to be $from ..."
      swaks --server "$server" --from "$from" --to "$to" --helo attacker.lab \
            --header "Subject: urgent wire transfer" --body "send the money" 2>&1
  - path: /etc/motd.raw
    content: |
      \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
        \033[1;31mcyber-lab-attacker\033[0m — \033[1mThe machine you attack from\033[0m
      \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m

        \033[1;33mYour IP:\033[0m 192.168.100.2   \033[1;33mTarget:\033[0m 192.168.100.1

        \033[1;33mUseful commands:\033[0m
          \033[0;32mnmap -p 22 192.168.100.1\033[0m           is the door open?
          \033[0;32mnc -w3 -z 192.168.100.1 22\033[0m         can I reach it right now?
          \033[0;32mburst-ssh 192.168.100.1 8\033[0m          knock 8 times, wrong key
          (then re-run 'nc -w3 -z' — is the door still open to YOU?)

        \033[1;33mCredentials:\033[0m  \033[1;36mlabuser\033[0m / \033[1;36mlabpass\033[0m
      \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m

runcmd:
  - chmod -x /etc/update-motd.d/* 2>/dev/null || true
  - sed -i 's/^#\?PrintMotd.*/PrintMotd yes/' /etc/ssh/sshd_config
  - sed -i 's/^session.*pam_motd.*/# &/' /etc/pam.d/sshd
  - printf '%b\n' "$(cat /etc/motd.raw)" > /etc/motd
  - rm -f /etc/motd.raw
  - netplan apply
  - systemctl restart ssh
  - echo "=== cyber-lab-attacker VM is ready! ==="
USERDATA

sed -i "s|__QLAB_SSH_PUB_KEY__|${QLAB_SSH_PUB_KEY:-}|g" "$LAB_DIR/user-data-attacker"

cat > "$LAB_DIR/meta-data-attacker" <<METADATA
instance-id: ${ATTACKER_VM}-001
local-hostname: ${ATTACKER_VM}
METADATA

success "Created cloud-init for $ATTACKER_VM"
echo ""

# =============================================
# Step 3: Generate cloud-init ISOs
# =============================================
info "Step 3: Cloud-init ISOs"
echo ""
check_dependency genisoimage || {
    warn "genisoimage not found. Install it with: sudo apt install genisoimage"
    exit 1
}

CIDATA_DEFENDER="$LAB_DIR/cidata-defender.iso"
genisoimage -output "$CIDATA_DEFENDER" -volid cidata -joliet -rock \
    -graft-points "user-data=$LAB_DIR/user-data-defender" "meta-data=$LAB_DIR/meta-data-defender" 2>/dev/null
success "Created cloud-init ISO: $CIDATA_DEFENDER"

CIDATA_ATTACKER="$LAB_DIR/cidata-attacker.iso"
genisoimage -output "$CIDATA_ATTACKER" -volid cidata -joliet -rock \
    -graft-points "user-data=$LAB_DIR/user-data-attacker" "meta-data=$LAB_DIR/meta-data-attacker" 2>/dev/null
success "Created cloud-init ISO: $CIDATA_ATTACKER"
echo ""

# =============================================
# Step 4: Create overlay disks
# =============================================
info "Step 4: Overlay disks"
echo ""

OVERLAY_DEFENDER="$LAB_DIR/${DEFENDER_VM}-disk.qcow2"
if [[ -f "$OVERLAY_DEFENDER" ]]; then rm -f "$OVERLAY_DEFENDER"; fi
create_overlay "$CLOUD_IMAGE_FILE" "$OVERLAY_DEFENDER" "${QLAB_DISK_SIZE:-6G}" || {
    error "Failed to create overlay disk for defender VM."
    exit 1
}

OVERLAY_ATTACKER="$LAB_DIR/${ATTACKER_VM}-disk.qcow2"
if [[ -f "$OVERLAY_ATTACKER" ]]; then rm -f "$OVERLAY_ATTACKER"; fi
create_overlay "$CLOUD_IMAGE_FILE" "$OVERLAY_ATTACKER" "${QLAB_DISK_SIZE:-6G}" || {
    error "Failed to create overlay disk for attacker VM."
    exit 1
}
echo ""

# =============================================
# Step 5: Start both VMs (internal LAN)
# =============================================
info "Step 5: Starting VMs (internal LAN: 192.168.100.0/24)"
echo ""

MEMORY_TOTAL=$(( MEMORY * 2 ))
check_host_resources "$MEMORY_TOTAL" 2
declare -a STARTED_VMS=()
register_vm_cleanup STARTED_VMS

info "Starting $DEFENDER_VM..."
start_vm_or_fail STARTED_VMS "$OVERLAY_DEFENDER" "$CIDATA_DEFENDER" "$MEMORY" "$DEFENDER_VM" auto \
    "-netdev" "socket,id=vlan1,mcast=${INTERNAL_MCAST}" \
    "-device" "virtio-net-pci,netdev=vlan1,mac=${DEFENDER_LAN_MAC}" || exit 1
echo ""

info "Starting $ATTACKER_VM..."
start_vm_or_fail STARTED_VMS "$OVERLAY_ATTACKER" "$CIDATA_ATTACKER" "$MEMORY" "$ATTACKER_VM" auto \
    "-netdev" "socket,id=vlan1,mcast=${INTERNAL_MCAST}" \
    "-device" "virtio-net-pci,netdev=vlan1,mac=${ATTACKER_LAN_MAC}" || exit 1

# Successful start — disable cleanup trap
trap - EXIT

echo ""
echo "============================================="
echo "  cyber-lab: Both VMs are booting"
echo "============================================="
echo ""
echo "  Defender VM (192.168.100.1):"
echo "    SSH:  qlab shell $DEFENDER_VM"
echo "    Log:  qlab log $DEFENDER_VM"
echo ""
echo "  Attacker VM (192.168.100.2):"
echo "    SSH:  qlab shell $ATTACKER_VM"
echo "    Log:  qlab log $ATTACKER_VM"
echo ""
echo "  Credentials (both VMs):  labuser / labpass"
echo ""
echo "  Wait ~90s for boot + package installation, then try the loop:"
echo "    1) attacker:  nc -w3 -z 192.168.100.1 22     # open to you"
echo "    2) attacker:  burst-ssh 192.168.100.1 8      # the attack"
echo "    3) defender:  sudo fail2ban-client status sshd  # the ban"
echo "    4) attacker:  nc -w3 -z 192.168.100.1 22     # now closed to you"
echo ""
echo "  Web app (vulnerable PHP) on the defender: http://192.168.100.1:8080"
echo "    attacker:  curl 'http://192.168.100.1:8080/?r=exec&cmd=id'   # RCE"
echo "    defender:  sudo touch /etc/cyber-lab/web-hardened; sudo systemctl restart cyber-web"
echo "    attacker:  curl 'http://192.168.100.1:8080/?r=exec&cmd=id'   # now refused"
echo ""
echo "  Docker/FORWARD trap on the defender: a container publishes :8888"
echo "    defender:  sudo ufw allow 22; sudo ufw deny 8888; sudo ufw --force enable"
echo "    attacker:  curl http://192.168.100.1:8888   # STILL reachable (the trap)"
echo "    defender:  sudo docker-forward-fix          # DROP in DOCKER-USER"
echo "    attacker:  curl http://192.168.100.1:8888   # now blocked"
echo ""
echo "  Mail (Postfix + local DNS) on the defender — the spoofed-sender loop:"
echo "    defender:  sudo mail-spf-off"
echo "    attacker:  spoof-mail ceo@boss.lab victim@mail.lab 192.168.100.1  # accepted"
echo "    defender:  sudo mail-spf-on"
echo "    attacker:  spoof-mail ceo@boss.lab victim@mail.lab 192.168.100.1  # 550 SPF fail"
echo ""
echo "  DMARC (opendkim+opendmarc) — reject on the DMARC verdict, SPF policy off:"
echo "    defender:  sudo mail-spf-off; sudo mail-dmarc-on"
echo "    attacker:  spoof-mail ...   # 550 5.7.1 rejected by DMARC policy"
echo ""
echo "  Or prove it all automatically:  qlab test cyber-lab"
echo ""
echo "  Stop both VMs:  qlab stop $PLUGIN_NAME"
echo "  Override resources:  QLAB_MEMORY=2048 qlab run ${PLUGIN_NAME}"
echo "============================================="
