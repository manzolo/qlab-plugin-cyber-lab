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
  - python3-systemd
  - php-cli
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
echo "  Or prove it all automatically:  qlab test cyber-lab"
echo ""
echo "  Stop both VMs:  qlab stop $PLUGIN_NAME"
echo "  Override resources:  QLAB_MEMORY=2048 qlab run ${PLUGIN_NAME}"
echo "============================================="
