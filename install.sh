#!/usr/bin/env bash
# cyber-lab install script

set -euo pipefail

echo ""
echo "  [cyber-lab] Installing..."
echo ""
echo "  This plugin creates TWO VMs on a private internal LAN"
echo "  (192.168.100.0/24), so the defender sees the attacker's"
echo "  REAL source IP — the whole point of the lab."
echo ""
echo "    1. cyber-lab-defender  (192.168.100.1)  — the machine you harden"
echo "       Runs sshd on the internal LAN, plus fail2ban + iptables."
echo ""
echo "    2. cyber-lab-attacker  (192.168.100.2)  — the machine you attack from"
echo "       Equipped with nmap, netcat, and a burst-ssh helper."
echo ""
echo "  The idea that holds the lab together:"
echo "    A running service is NOT a working defense. The proof of a"
echo "    defense is the ban in the register and the attacker locked"
echo "    out at the packet level — never 'systemctl is-active'."
echo ""

mkdir -p lab

echo "  Checking dependencies..."
local_ok=true
for cmd in qemu-system-x86_64 qemu-img genisoimage curl; do
    if command -v "$cmd" &>/dev/null; then
        echo "    [OK] $cmd"
    else
        echo "    [!!] $cmd — not found (install before running)"
        local_ok=false
    fi
done

if [[ "$local_ok" == true ]]; then
    echo ""
    echo "  All dependencies are available."
else
    echo ""
    echo "  Some dependencies are missing. Install them with:"
    echo "    sudo apt install qemu-kvm qemu-utils genisoimage curl"
fi

echo ""
echo "  [cyber-lab] Installation complete."
echo "  Run with: qlab run cyber-lab"
