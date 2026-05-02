#!/usr/bin/env bash
# Run as root: sudo bash setup_sudo.sh
set -e

SUDOERS_FILE="/etc/sudoers.d/proflupinmind-tools"

cat > "$SUDOERS_FILE" <<'EOF'
# ProfLupinMind — NOPASSWD sudo for tools that require root
kali ALL=(ALL) NOPASSWD: /usr/bin/nmap
kali ALL=(ALL) NOPASSWD: /usr/bin/masscan
kali ALL=(ALL) NOPASSWD: /usr/sbin/netdiscover
kali ALL=(ALL) NOPASSWD: /usr/sbin/arp-scan
kali ALL=(ALL) NOPASSWD: /usr/sbin/hping3
kali ALL=(ALL) NOPASSWD: /usr/bin/ike-scan
kali ALL=(ALL) NOPASSWD: /usr/sbin/p0f
kali ALL=(ALL) NOPASSWD: /usr/sbin/airmon-ng
kali ALL=(ALL) NOPASSWD: /usr/sbin/airodump-ng
kali ALL=(ALL) NOPASSWD: /usr/sbin/aireplay-ng
kali ALL=(ALL) NOPASSWD: /usr/bin/wifite
kali ALL=(ALL) NOPASSWD: /usr/sbin/wifite
kali ALL=(ALL) NOPASSWD: /usr/bin/reaver
kali ALL=(ALL) NOPASSWD: /usr/bin/bettercap
kali ALL=(ALL) NOPASSWD: /usr/bin/kismet
kali ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
kali ALL=(ALL) NOPASSWD: /usr/bin/tshark
kali ALL=(ALL) NOPASSWD: /usr/sbin/responder
kali ALL=(ALL) NOPASSWD: /usr/bin/ettercap
kali ALL=(ALL) NOPASSWD: /usr/bin/arpspoof
kali ALL=(ALL) NOPASSWD: /usr/bin/mitm6
kali ALL=(ALL) NOPASSWD: /usr/bin/setoolkit
kali ALL=(ALL) NOPASSWD: /usr/bin/msfconsole
kali ALL=(ALL) NOPASSWD: /usr/bin/msfdb
kali ALL=(ALL) NOPASSWD: /usr/local/bin/kube-bench
kali ALL=(ALL) NOPASSWD: /usr/local/bin/docker-bench-security
kali ALL=(ALL) NOPASSWD: /usr/bin/falco
EOF

chmod 440 "$SUDOERS_FILE"
if visudo -c -f "$SUDOERS_FILE"; then
    echo "Sudoers file installed successfully."
else
    echo "ERROR: invalid sudoers syntax — file removed."
    rm -f "$SUDOERS_FILE"
    exit 1
fi

# Patch wifite color.py so it works without a TTY (non-interactive executors)
COLOR_PY="/usr/lib/python3/dist-packages/wifite/util/color.py"
if grep -q "os.popen('stty size'" "$COLOR_PY" 2>/dev/null; then
    cp "$COLOR_PY" "${COLOR_PY}.bak"
    python3 - <<'PYEOF'
path = "/usr/lib/python3/dist-packages/wifite/util/color.py"
old = "        (rows, columns) = os.popen('stty size', 'r').read().split()"
new = "        result = os.popen('stty size', 'r').read().strip()\n        rows, columns = result.split() if result else ('24', '80')"
content = open(path).read()
open(path, 'w').write(content.replace(old, new))
PYEOF
    echo "wifite color.py patched for non-TTY support."
else
    echo "wifite color.py already patched or not found — skipping."
fi
