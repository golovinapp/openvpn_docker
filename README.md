# OpenVPN in Docker (UDP/443)

Minimal, production-ready OpenVPN setup using `kylemanna/openvpn`.  
Deploys automatically via Bash script and includes command-line user management.

---

## Features
- Works on Debian 12+ or Ubuntu with Docker  
- Asks for domain name (or detects public IP automatically)  
- Certificate-based auth only (no PAM/password)  
- Secure defaults: UDP 443, AES-256-GCM, no compression  
- Built-in user management script (`ovpn-users.sh`)  
- Auto-creates first client profile (`user.ovpn`)

---

## Quick start
```bash
curl -O https://raw.githubusercontent.com/golovinapp/openvpn_docker/refs/heads/main/deploy-ovpn.sh
sudo bash deploy-openvpn.sh
```
The script installs Docker (if missing), configures OpenVPN, and generates  
`/opt/openvpn/clients/user.ovpn`.

---

## User management
```
cd /opt/openvpn/scripts
./ovpn-users.sh add <name>       # create client and save profile
./ovpn-users.sh del <name>       # revoke certificate
./ovpn-users.sh list             # list valid/revoked users
./ovpn-users.sh connected        # show active sessions
./ovpn-users.sh show <name>      # print .ovpn to stdout
```

---

## Client setup
Import the generated `.ovpn` file into OpenVPN Connect, Tunnelblick,  
or run `openvpn --config user.ovpn` on Linux.

---

## Troubleshooting

**Login prompt (“Auth Username/Password was not provided”)**  
Remove any PAM lines:
```bash
docker compose exec -T openvpn sh -c "sed -i '/openvpn-plugin-auth-pam.so/d;/username-as-common-name/d' /etc/openvpn/openvpn.conf"
docker compose restart openvpn
```

**comp-lzo warnings**  
Delete from config:
```bash
docker compose exec -T openvpn sh -c "sed -i '/^comp-lzo/d' /etc/openvpn/openvpn.conf"
```

**No status file yet**  
Run `./ovpn-users.sh connected` – it will enable the status log automatically.

**Firewall**  
Allow UDP 443: `sudo ufw allow 443/udp`

---

## Credits
Based on [kylemanna/openvpn](https://github.com/kylemanna/docker-openvpn).  
Extended with auto IP detection, config cleanup, and CLI management.
