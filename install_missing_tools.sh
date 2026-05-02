#!/usr/bin/env bash
# ============================================================
# ProfLupinMind — Install All Missing Tools
# Run: sudo bash install_missing_tools.sh
# ============================================================
set -euo pipefail

GREEN='\033[92m'; RED='\033[91m'; YELLOW='\033[93m'; BOLD='\033[1m'; RST='\033[0m'

ok()   { echo -e "${GREEN}✅ $*${RST}"; }
fail() { echo -e "${RED}❌ FAILED: $*${RST}"; }
info() { echo -e "${YELLOW}⚡ $*${RST}"; }
head() { echo -e "\n${BOLD}══════════════════════════════════════${RST}"; echo -e "${BOLD}  $*${RST}"; echo -e "${BOLD}══════════════════════════════════════${RST}"; }

# Must run as root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Run with sudo: sudo bash $0${RST}"; exit 1
fi

GOBIN="/home/kali/go/bin"
export PATH="$GOBIN:/usr/local/bin:$PATH"
PROFLUPINMIND_VENV="/home/kali/Desktop/kaliwithAI/.venv"

# ── Helper: install go tool as kali user ──────────────────────────────────────
go_install() {
  local pkg="$1" bin="$2"
  if command -v "$bin" &>/dev/null; then
    ok "$bin already installed"; return
  fi
  info "go install $pkg"
  sudo -u kali bash -c "export PATH=$GOBIN:/usr/local/go/bin:\$PATH; go install $pkg 2>&1" \
    && ok "$bin" || fail "$bin"
}

# ── Helper: pip install ───────────────────────────────────────────────────────
pip_install() {
  local pkg="$1" bin="${2:-$1}"
  if command -v "$bin" &>/dev/null 2>&1; then
    ok "$bin already installed"; return
  fi
  info "pip install $pkg"
  pip3 install --break-system-packages -q "$pkg" 2>&1 | tail -1 \
    && ok "$pkg" || fail "$pkg"
}

# ── Helper: apt install ───────────────────────────────────────────────────────
apt_install() {
  local pkg="$1" bin="${2:-$1}"
  if command -v "$bin" &>/dev/null 2>&1; then
    ok "$bin already installed"; return
  fi
  info "apt install $pkg"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$pkg" 2>&1 | tail -3 \
    && ok "$pkg" || fail "$pkg"
}

# ── Helper: download binary ───────────────────────────────────────────────────
dl_binary() {
  local name="$1" url="$2" dest="${3:-/usr/local/bin/$1}"
  if command -v "$name" &>/dev/null 2>&1; then
    ok "$name already installed"; return
  fi
  info "Downloading $name"
  curl -fsSL "$url" -o "$dest" && chmod +x "$dest" \
    && ok "$name" || fail "$name"
}

dl_tarball() {
  local name="$1" url="$2" binary="${3:-$1}"
  if command -v "$name" &>/dev/null 2>&1; then
    ok "$name already installed"; return
  fi
  info "Downloading $name"
  tmp=$(mktemp -d)
  curl -fsSL "$url" | tar xz -C "$tmp" 2>/dev/null \
    && cp "$tmp/$binary" /usr/local/bin/"$name" \
    && chmod +x /usr/local/bin/"$name" \
    && rm -rf "$tmp" \
    && ok "$name" || { rm -rf "$tmp"; fail "$name"; }
}

# ─────────────────────────────────────────────────────────────────────────────
head "1 · APT packages"
# ─────────────────────────────────────────────────────────────────────────────
info "Running apt-get update..."
apt-get update -q

apt_install rustscan     rustscan
apt_install dirsearch    dirsearch
apt_install gdb          gdb
apt_install steghide     steghide
apt_install foremost     foremost
apt_install hashpump     hashpump
apt_install dotdotpwn    dotdotpwn
apt_install xsser        xsser
apt_install ruby         ruby   # needed for one_gadget
apt_install ruby-dev     ruby
apt_install build-essential gcc

# ─────────────────────────────────────────────────────────────────────────────
head "2 · Go tools"
# ─────────────────────────────────────────────────────────────────────────────
# Ensure Go is available
if ! command -v go &>/dev/null; then
  fail "Go not found — install Go first: https://go.dev/dl/";
else
  go_install "github.com/hahwul/dalfox/v2@latest"                           dalfox
  go_install "github.com/projectdiscovery/katana/cmd/katana@latest"         katana
  go_install "github.com/hakluke/hakrawler@latest"                          hakrawler
  go_install "github.com/lc/gau/v2/cmd/gau@latest"                         gau
  go_install "github.com/tomnomnom/waybackurls@latest"                      waybackurls
  go_install "github.com/tomnomnom/anew@latest"                             anew
  go_install "github.com/tomnomnom/qsreplace@latest"                        qsreplace
  go_install "github.com/003random/getJS@latest"                            getJS
fi

# ─────────────────────────────────────────────────────────────────────────────
head "3 · Python / pip tools"
# ─────────────────────────────────────────────────────────────────────────────
pip_install volatility3       vol
pip_install jwt_tool          jwt_tool
pip_install pacu              pacu

# graphqlmap — not on PyPI, clone from GitHub
if ! command -v graphqlmap &>/dev/null; then
  info "Installing graphqlmap from GitHub"
  cd /opt
  git clone -q https://github.com/swisskyrepo/GraphQLmap.git graphqlmap 2>/dev/null || true
  ln -sf /opt/graphqlmap/graphqlmap.py /usr/local/bin/graphqlmap
  chmod +x /opt/graphqlmap/graphqlmap.py
  ok "graphqlmap"
else
  ok "graphqlmap already installed"
fi

# jaeles — Go, but sometimes needs git clone
if ! command -v jaeles &>/dev/null; then
  info "Installing jaeles"
  sudo -u kali bash -c "export PATH=$GOBIN:/usr/local/go/bin:\$PATH; go install github.com/jaeles-project/jaeles@latest 2>&1" \
    && ok "jaeles" || fail "jaeles (try: go install github.com/jaeles-project/jaeles@latest)"
else
  ok "jaeles already installed"
fi

# ─────────────────────────────────────────────────────────────────────────────
head "4 · Ruby gems"
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v one_gadget &>/dev/null; then
  info "gem install one_gadget"
  gem install one_gadget -q && ok "one_gadget" || fail "one_gadget"
else
  ok "one_gadget already installed"
fi

# ─────────────────────────────────────────────────────────────────────────────
head "5 · Standalone binaries"
# ─────────────────────────────────────────────────────────────────────────────

# terrascan
if ! command -v terrascan &>/dev/null; then
  info "Downloading terrascan..."
  TERRASCAN_VER=$(curl -fsSL "https://api.github.com/repos/tenable/terrascan/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')
  dl_tarball terrascan \
    "https://github.com/tenable/terrascan/releases/latest/download/terrascan_${TERRASCAN_VER}_Linux_x86_64.tar.gz" \
    terrascan || fail "terrascan (manual: https://github.com/tenable/terrascan/releases)"
else
  ok "terrascan already installed"
fi

# kube-bench
if ! command -v kube-bench &>/dev/null; then
  info "Downloading kube-bench..."
  dl_tarball kube-bench \
    "https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_linux_amd64.tar.gz" \
    kube-bench || fail "kube-bench (manual: https://github.com/aquasecurity/kube-bench/releases)"
else
  ok "kube-bench already installed"
fi

# pwninit
if ! command -v pwninit &>/dev/null; then
  info "Downloading pwninit binary..."
  PWNINIT_URL="https://github.com/io12/pwninit/releases/latest/download/pwninit"
  dl_binary pwninit "$PWNINIT_URL" /usr/local/bin/pwninit \
    || fail "pwninit (manual: https://github.com/io12/pwninit/releases)"
else
  ok "pwninit already installed"
fi

# ─────────────────────────────────────────────────────────────────────────────
head "6 · Symlinking Go binaries to /usr/local/bin"
# ─────────────────────────────────────────────────────────────────────────────
for bin in dalfox katana hakrawler gau waybackurls anew qsreplace jaeles getJS; do
  src="$GOBIN/$bin"
  dst="/usr/local/bin/$bin"
  if [[ -f "$src" && ! -e "$dst" ]]; then
    ln -sf "$src" "$dst" && ok "linked $bin → /usr/local/bin/"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
head "Done — re-run test_tools.py to verify"
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "  python3 /home/kali/Desktop/kaliwithAI/test_tools.py --version"
echo ""
