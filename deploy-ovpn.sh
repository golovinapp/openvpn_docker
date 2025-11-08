#!/usr/bin/env bash
set -euo pipefail

# === OpenVPN on Docker (UDP/443) — domain or auto public IP ===
# Works on Debian 12. Requires root (or sudo).

# --- settings ---
APP_DIR="/opt/openvpn"
FIRST_USER="${FIRST_USER:-user}"     # можно переопределить переменной окружения
OVPN_PORT="${OVPN_PORT:-443}"
IMAGE="kylemanna/openvpn:latest"
SVC="openvpn"

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must run as root. Try: sudo bash $0" >&2
    exit 1
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

choose_compose_cmd() {
  if have docker && docker compose version >/dev/null 2>&1; then
    echo "docker compose"
  elif have docker-compose; then
    echo "docker-compose"
  else
    echo ""
  fi
}

install_docker_if_needed() {
  if ! have docker; then
    echo "[*] Docker not found. Installing Docker Engine..."
    apt-get update
    apt-get install -y ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
  fi
}

detect_public_ip() {
  # несколько источников с таймаутами
  for url in \
    "https://api.ipify.org" \
    "https://ifconfig.me" \
    "https://ipv4.icanhazip.com" \
    "https://checkip.amazonaws.com"
  do
    ip="$(curl -4s --max-time 4 "$url" | tr -d '\r' | head -n1 || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      echo "$ip"; return 0
    fi
  done
  return 1
}

ask_host() {
  echo "Use custom domain name for VPN server? [y/N]"
  read -r yn
  if [[ "$yn" =~ ^[Yy]$ ]]; then
    echo -n "Enter domain (FQDN), e.g. vpn.example.com: "
    read -r dom
    # минимальная проверка домена
    if [[ ! "$dom" =~ ^[A-Za-z0-9.-]+$ ]]; then
      echo "Invalid domain format." >&2; exit 1
    fi
    OVPN_HOST="$dom"
  else
    echo "[*] Detecting public IP..."
    OVPN_HOST="$(detect_public_ip || true)"
    if [[ -z "${OVPN_HOST:-}" ]]; then
      echo "Could not detect public IP automatically. Please rerun and specify a domain." >&2
      exit 1
    fi
    echo "[OK] Public IP: $OVPN_HOST"
  fi
}

ensure_dirs() {
  mkdir -p "$APP_DIR"/{data,clients,scripts}
}

write_compose() {
  cat > "$APP_DIR/docker-compose.yml" <<YML
services:
  ${SVC}:
    image: ${IMAGE}
    container_name: ${SVC}
    restart: unless-stopped
    cap_add: [ "NET_ADMIN" ]
    devices: [ "/dev/net/tun:/dev/net/tun" ]
    volumes:
      - ./data:/etc/openvpn
      - ./clients:/clients
    ports:
      - "${OVPN_PORT}:${OVPN_PORT}/udp"
    sysctls:
      - net.ipv6.conf.all.forwarding=1
      - net.ipv6.conf.default.forwarding=1
YML
}

gen_users_script() {
  cat > "$APP_DIR/scripts/ovpn-users.sh" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."  # -> /opt/openvpn
COMPOSE="docker compose"; SVC=openvpn

have() { command -v "$1" >/dev/null 2>&1; }
if ! docker compose version >/dev/null 2>&1 && have docker-compose; then
  COMPOSE="docker-compose"
fi

ensure_up() {
  $COMPOSE ps --services --filter "status=running" | grep -q "^${SVC}$" || $COMPOSE up -d ${SVC}
}

cmd_add() {
  local u="${1:-}"; [[ -z "$u" ]] && { echo "Usage: $0 add <username>"; exit 1; }
  ensure_up
  $COMPOSE run --rm ${SVC} easyrsa build-client-full "$u" nopass
  mkdir -p clients
  $COMPOSE run --rm ${SVC} ovpn_getclient "$u" > "clients/${u}.ovpn"
  echo "[OK] Created: clients/${u}.ovpn"
}

cmd_del() {
  local u="${1:-}"; [[ -z "$u" ]] && { echo "Usage: $0 del <username>"; exit 1; }
  ensure_up
  $COMPOSE run --rm ${SVC} easyrsa revoke "$u"
  $COMPOSE run --rm ${SVC} easyrsa gen-crl
  $COMPOSE exec -T ${SVC} ovpn_copy_server_files
  $COMPOSE restart ${SVC}
  echo "[OK] Revoked: ${u}"
}

cmd_show() {
  local u="${1:-}"; [[ -z "$u" ]] && { echo "Usage: $0 show <username>"; exit 1; }
  if [[ -f "clients/${u}.ovpn" ]]; then
    cat "clients/${u}.ovpn"
  else
    ensure_up
    $COMPOSE run --rm ${SVC} ovpn_getclient "$u"
  fi
}

cmd_connected() {
  ensure_up
  # ensure status log in /tmp
  $COMPOSE exec -T ${SVC} sh -lc '
    CONF=/etc/openvpn/openvpn.conf
    if ! grep -q "^status /tmp/openvpn-status.log" "$CONF"; then
      sed -i "/^status /d;/^status-version /d" "$CONF"
      printf "\nstatus /tmp/openvpn-status.log 10\nstatus-version 2\n" >> "$CONF"
      exit 10
    fi
  ' || $COMPOSE restart ${SVC} >/dev/null
  sleep 1
  $COMPOSE exec -T ${SVC} cat /tmp/openvpn-status.log 2>/dev/null | awk -F',' '
    BEGIN {
      in_clients=0;
      printf "%-20s %-22s %-14s %-14s %-22s\n",
             "COMMON_NAME","REAL_ADDRESS","BYTES_RX","BYTES_TX","CONNECTED_SINCE"
    }
    /^Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since/ { in_clients=1; next }
    /^ROUTING TABLE/ { in_clients=0 }
    in_clients && NF>=5 && $1!="Common Name" {
      printf "%-20s %-22s %-14s %-14s %-22s\n", $1, $2, $3, $4, $5
    }
  ' || { echo "No status file yet"; exit 1; }
}

cmd_list() {
  ensure_up
  $COMPOSE exec -T ${SVC} sh -c '
  INDEX=/etc/openvpn/pki/index.txt
  ISSUED=/etc/openvpn/pki/issued
  CONF=/etc/openvpn/openvpn.conf
  SERVER_CRT=$(basename "$(awk "/^cert[[:space:]]/ {print \$2; exit}" "$CONF")")

  printf "%-10s  %-25s  %-24s  %s\n" "STATUS" "CN" "EXPIRES(UTC)" "SERIAL"
  for crt in "$ISSUED"/*.crt; do
    [ -e "$crt" ] || { echo "(no certs)"; break; }
    [ "$(basename "$crt")" = "$SERVER_CRT" ] && continue
    CN=$(openssl x509 -in "$crt" -noout -subject -nameopt RFC2253 | sed -n "s/^subject=CN=//p" | cut -d, -f1)
    SERIAL=$(openssl x509 -in "$crt" -noout -serial | cut -d= -f2)
    EXPIRES=$(openssl x509 -in "$crt" -noout -enddate | cut -d= -f2)
    STATUS=VALID
    if [ -f "$INDEX" ] && grep -q "^[R].*CN=$CN" "$INDEX"; then STATUS=REVOKED; fi
    printf "%-10s  %-25s  %-24s  %s\n" "$STATUS" "$CN" "$EXPIRES" "$SERIAL"
  done
  '
}

usage() {
  cat <<EOF
Usage: $0 <command> [args]
  add <user>         Create client and save clients/<user>.ovpn
  del <user>         Revoke client and update CRL
  list               List clients (VALID/REVOKED)
  connected          Show active sessions
  show <user>        Print .ovpn to stdout

Examples:
  $0 add alice
  $0 list
  $0 connected
  $0 show alice > alice.ovpn
  $0 del alice
EOF
}

case "${1:-}" in
  add) shift; cmd_add "$@";;
  del|rm) shift; cmd_del "$@";;
  list) shift; cmd_list "$@";;
  connected) shift; cmd_connected "$@";;
  show|get) shift; cmd_show "$@";;
  *) usage;;
esac
EOS
  chmod +x "$APP_DIR/scripts/ovpn-users.sh"
}

clean_openvpn_conf() {
  # remove PAM plugin, username-as-common-name, comp-lzo; enable status in /tmp
  local CONF="$APP_DIR/data/openvpn.conf"
  # If config not yet present inside bind mount, exec inside container
  if [[ ! -f "$CONF" ]]; then
    $COMPOSE exec -T "$SVC" sh -lc '
      CONF=/etc/openvpn/openvpn.conf
      sed -i "/openvpn-plugin-auth-pam.so/d; /username-as-common-name/d" "$CONF"
      sed -i "/^comp-lzo/d" "$CONF"
      if ! grep -q "^status /tmp/openvpn-status.log" "$CONF"; then
        printf "\nstatus /tmp/openvpn-status.log 10\nstatus-version 2\n" >> "$CONF"
      fi
    '
  else
    sed -i '/openvpn-plugin-auth-pam.so/d; /username-as-common-name/d' "$CONF" || true
    sed -i '/^comp-lzo/d' "$CONF" || true
    grep -q '^status /tmp/openvpn-status.log' "$CONF" || \
      printf "\nstatus /tmp/openvpn-status.log 10\nstatus-version 2\n" >> "$CONF"
  fi
}

open_firewall_if_present() {
  if have ufw; then ufw allow "${OVPN_PORT}/udp" || true; fi
  if have firewall-cmd; then firewall-cmd --add-port="${OVPN_PORT}/udp" --permanent && firewall-cmd --reload || true; fi
}

# --- main ---
need_root
install_docker_if_needed

COMPOSE="$(choose_compose_cmd)"
if [[ -z "$COMPOSE" ]]; then
  echo "docker compose not found. Install Docker Compose plugin or docker-compose." >&2
  exit 1
fi

ask_host
ensure_dirs
write_compose

echo "[*] Bringing up container..."
cd "$APP_DIR"
$COMPOSE up -d

echo "[*] Generating server config for udp://${OVPN_HOST}:${OVPN_PORT} ..."
$COMPOSE run --rm "$SVC" ovpn_genconfig -u "udp://${OVPN_HOST}:${OVPN_PORT}" \
  -p "redirect-gateway def1" \
  -p "dhcp-option DNS 1.1.1.1" \
  -p "dhcp-option DNS 1.0.0.1" \
  -N -2 -C AES-256-GCM -a SHA256

echo "[*] Initializing PKI (nopass)..."
$COMPOSE run --rm "$SVC" ovpn_initpki nopass

# cleanup config and enable status
clean_openvpn_conf

echo "[*] Restarting OpenVPN..."
$COMPOSE restart "$SVC"

echo "[*] Creating first client: ${FIRST_USER}"
$COMPOSE run --rm "$SVC" easyrsa build-client-full "${FIRST_USER}" nopass
$COMPOSE run --rm "$SVC" ovpn_getclient "${FIRST_USER}" > "clients/${FIRST_USER}.ovpn"

# users manager
gen_users_script

open_firewall_if_present

echo
echo "=== Done ==="
echo "OVPN host: ${OVPN_HOST}"
echo "Client profile: ${APP_DIR}/clients/${FIRST_USER}.ovpn"
echo "User manager:   ${APP_DIR}/scripts/ovpn-users.sh  (add/del/show/list/connected)"
