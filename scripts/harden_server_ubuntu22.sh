#!/usr/bin/env bash
set -euo pipefail

# One-shot hardening for sdn demo on Ubuntu 22.04
# - nftables firewall (keeps SSH open automatically)
# - Nginx reverse proxy to the webapp (default http://127.0.0.1:5000)
# - ModSecurity + OWASP CRS
# - Rate limiting + connection limiting
# - sysctl tuning + file descriptor limits
#
# IMPORTANT:
# - Run this on the Ubuntu server as a sudo-capable user.
# - This script will modify firewall and nginx config.

WEB_UPSTREAM_HOST="${WEB_UPSTREAM_HOST:-127.0.0.1}"
WEB_UPSTREAM_PORT="${WEB_UPSTREAM_PORT:-5000}"

MODSEC_ENABLE="${MODSEC_ENABLE:-1}"
_MODSEC_AVAILABLE="0"

CLOUDFLARE_MODE="${CLOUDFLARE_MODE:-0}"
CLOUDFLARE_ALLOWLIST_NGINX="${CLOUDFLARE_ALLOWLIST_NGINX:-0}"
CLOUDFLARE_ALLOWLIST_NFT="${CLOUDFLARE_ALLOWLIST_NFT:-0}"
CLOUDFLARE_AUTO_UPDATE="${CLOUDFLARE_AUTO_UPDATE:-1}"

# If you later obtain a proper certificate (Let's Encrypt), replace these.
TLS_CERT_PATH="${TLS_CERT_PATH:-/etc/ssl/sdn/sdn.crt}"
TLS_KEY_PATH="${TLS_KEY_PATH:-/etc/ssl/sdn/sdn.key}"

# Nginx limits (tune for demo)
NGINX_LIMIT_REQ_RATE="${NGINX_LIMIT_REQ_RATE:-10r/s}"      # requests per second per IP
NGINX_LIMIT_REQ_BURST="${NGINX_LIMIT_REQ_BURST:-40}"
NGINX_LIMIT_CONN="${NGINX_LIMIT_CONN:-20}"                 # concurrent conns per IP

# Firewall limits (coarse protection; main limiting happens in Nginx)
FW_HTTP_NEW_CONN_RATE="${FW_HTTP_NEW_CONN_RATE:-50/second}" # global-ish rate for new conns
FW_HTTP_NEW_CONN_BURST="${FW_HTTP_NEW_CONN_BURST:-120}"

# If you use a Cloudflare Tunnel (no domain needed), you can keep 80/443 CLOSED on the server.
# - 1: expose 80/443 to the internet (normal reverse proxy mode)
# - 0: do NOT expose 80/443 (tunnel-only mode; web only reachable via the tunnel URL)
FW_EXPOSE_WEB_PORTS="${FW_EXPOSE_WEB_PORTS:-1}"

# - 1: apply nftables rules (recommended)
# - 0: skip firewall changes (useful if you're worried about SSH lockout during demo)
FW_ENABLE="${FW_ENABLE:-1}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

fetch_to_file() {
  local url out
  url="$1"
  out="$2"

  as_root mkdir -p "$(dirname "${out}")"
  if ! as_root curl -fsSL --connect-timeout 8 --max-time 20 --retry 3 --retry-delay 2 "${url}" -o "${out}"; then
    return 1
  fi
  if [[ ! -s "${out}" ]]; then
    return 1
  fi
  return 0
}

setup_cloudflare_files() {
  if [[ "${CLOUDFLARE_MODE}" != "1" ]]; then
    return 0
  fi

  local base
  base="/etc/sdn/cloudflare"
  as_root mkdir -p "${base}"

  # Create safe defaults so nginx includes won't break even if fetch fails.
  # Note: without set_real_ip_from entries, Nginx will not trust CF-Connecting-IP.
  cat <<'EOF' | as_root tee "${base}/nginx_realip.conf" >/dev/null
real_ip_header CF-Connecting-IP;
real_ip_recursive on;
EOF
  cat <<'EOF' | as_root tee "${base}/nginx_geo.conf" >/dev/null
# Cloudflare allowlist using geo on the *original* peer IP before real_ip rewrite.
# When requests come via Cloudflare, $realip_remote_addr is the Cloudflare edge IP.
geo $realip_remote_addr $sdn_from_cf {
  default 0;
}
EOF

  if ! fetch_to_file "https://www.cloudflare.com/ips-v4" "${base}/ips-v4.txt"; then
    echo "[!] Failed to fetch Cloudflare IPv4 ranges. Continuing without Cloudflare allowlist/real_ip." >&2
    return 0
  fi
  if ! fetch_to_file "https://www.cloudflare.com/ips-v6" "${base}/ips-v6.txt"; then
    echo "[!] Failed to fetch Cloudflare IPv6 ranges. Continuing with IPv4 only." >&2
    as_root : > "${base}/ips-v6.txt"
  fi

  as_root awk '{print "set_real_ip_from " $0 ";"}' "${base}/ips-v4.txt" >> "${base}/nginx_realip.conf" || true
  as_root awk '{print "set_real_ip_from " $0 ";"}' "${base}/ips-v6.txt" >> "${base}/nginx_realip.conf" || true

  # Populate geo map only after we have ranges.
  as_root awk '{print "  " $0 " 1;"}' "${base}/ips-v4.txt" >> "${base}/nginx_geo.conf" || true
  as_root awk '{print "  " $0 " 1;"}' "${base}/ips-v6.txt" >> "${base}/nginx_geo.conf" || true
  as_root printf '%s\n' '}' >> "${base}/nginx_geo.conf"

  if [[ "${CLOUDFLARE_ALLOWLIST_NFT}" = "1" ]]; then
    cat <<'EOF' | as_root tee "${base}/nft_cloudflare_sets.nft" >/dev/null
define CF4 = {
EOF
    as_root awk '{print "  " $0 ","}' "${base}/ips-v4.txt" >> "${base}/nft_cloudflare_sets.nft" || true
    cat <<'EOF' | as_root tee -a "${base}/nft_cloudflare_sets.nft" >/dev/null
}

define CF6 = {
EOF
    as_root awk '{print "  " $0 ","}' "${base}/ips-v6.txt" >> "${base}/nft_cloudflare_sets.nft" || true
    cat <<'EOF' | as_root tee -a "${base}/nft_cloudflare_sets.nft" >/dev/null
}
EOF
  fi

  as_root mkdir -p /etc/nginx/conf.d
  as_root ln -sf "${base}/nginx_realip.conf" /etc/nginx/conf.d/sdn_cloudflare_realip.conf
  as_root ln -sf "${base}/nginx_geo.conf" /etc/nginx/conf.d/sdn_cloudflare_geo.conf

  if [[ "${CLOUDFLARE_AUTO_UPDATE}" = "1" ]]; then
    cat <<'EOF' | as_root tee /usr/local/sbin/sdn-cloudflare-update.sh >/dev/null
#!/usr/bin/env bash
set -euo pipefail

BASE=/etc/sdn/cloudflare

curl -fsSL --connect-timeout 8 --max-time 25 --retry 3 --retry-delay 2 https://www.cloudflare.com/ips-v4 -o "$BASE/ips-v4.txt"
curl -fsSL --connect-timeout 8 --max-time 25 --retry 3 --retry-delay 2 https://www.cloudflare.com/ips-v6 -o "$BASE/ips-v6.txt" || true

: > "$BASE/nginx_realip.conf"
{
  echo 'real_ip_header CF-Connecting-IP;'
  echo 'real_ip_recursive on;'
  awk '{print "set_real_ip_from " $0 ";"}' "$BASE/ips-v4.txt" || true
  awk '{print "set_real_ip_from " $0 ";"}' "$BASE/ips-v6.txt" || true
} >> "$BASE/nginx_realip.conf"

: > "$BASE/nginx_geo.conf"
{
  echo '# Cloudflare allowlist using geo on the *original* peer IP before real_ip rewrite.'
  echo '# When requests come via Cloudflare, $realip_remote_addr is the Cloudflare edge IP.'
  echo 'geo $realip_remote_addr $sdn_from_cf {'
  echo '  default 0;'
  awk '{print "  " $0 " 1;"}' "$BASE/ips-v4.txt" || true
  awk '{print "  " $0 " 1;"}' "$BASE/ips-v6.txt" || true
  echo '}'
} >> "$BASE/nginx_geo.conf"

nginx -t
systemctl reload nginx || systemctl restart nginx
EOF
    as_root chmod +x /usr/local/sbin/sdn-cloudflare-update.sh

    cat <<'EOF' | as_root tee /etc/systemd/system/sdn-cloudflare-update.service >/dev/null
[Unit]
Description=Update Cloudflare IP ranges for sdn

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sdn-cloudflare-update.sh
EOF

    cat <<'EOF' | as_root tee /etc/systemd/system/sdn-cloudflare-update.timer >/dev/null
[Unit]
Description=Daily update of Cloudflare IP ranges for sdn

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
    as_root systemctl daemon-reload
    as_root systemctl enable --now sdn-cloudflare-update.timer || true
  fi
}

as_root() {
  if [[ $(id -u) -ne 0 ]]; then
    sudo -E "$@"
  else
    "$@"
  fi
}

get_ssh_port() {
  # Try to detect sshd listening port from ss; fallback to 22.
  local p
  p="$(as_root ss -ltnp 2>/dev/null | awk '/sshd/ && /LISTEN/ {print $4}' | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | head -n 1)" || true
  if [[ -n "${p}" ]]; then
    echo "${p}"
  else
    echo "22"
  fi
}

ensure_packages() {
  local codename
  codename="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}")"
  if [[ -z "${codename}" ]]; then
    codename="unknown"
  fi
  echo "[i] Detected Ubuntu codename: ${codename}"

  as_root apt-get update -y
  as_root apt-get install -y nftables openssl curl nginx

  if [[ "${MODSEC_ENABLE}" != "1" ]]; then
    echo "[i] ModSecurity disabled via MODSEC_ENABLE=0"
    return 0
  fi

  if as_root apt-cache show libnginx-mod-http-modsecurity >/dev/null 2>&1; then
    as_root apt-get install -y libnginx-mod-http-modsecurity
    _MODSEC_AVAILABLE="1"
  else
    echo "[!] Package libnginx-mod-http-modsecurity not found in APT repos (common on Ubuntu focal/20.04)."
    echo "[!] Continuing WITHOUT ModSecurity WAF. Nginx rate limiting + firewall will still be applied."
    echo "[!] For full WAF (ModSecurity+OWASP CRS), use Ubuntu 22.04 (jammy) or provide a ModSecurity-enabled Nginx build."
    _MODSEC_AVAILABLE="0"
  fi

  if [[ "${_MODSEC_AVAILABLE}" = "1" ]]; then
    if as_root apt-cache show modsecurity-crs >/dev/null 2>&1; then
      as_root apt-get install -y modsecurity-crs
    else
      echo "[!] Package modsecurity-crs not found; ModSecurity will run without OWASP CRS rules."
    fi
  fi
}

setup_modsecurity() {
  if [[ "${MODSEC_ENABLE}" != "1" || "${_MODSEC_AVAILABLE}" != "1" ]]; then
    return 0
  fi
  # modsecurity.conf
  if [[ -f /etc/modsecurity/modsecurity.conf-recommended && ! -f /etc/modsecurity/modsecurity.conf ]]; then
    as_root cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
  fi
  # Enable blocking mode
  if [[ -f /etc/modsecurity/modsecurity.conf ]]; then
    as_root sed -i 's/^\s*SecRuleEngine\s\+DetectionOnly\s*$/SecRuleEngine On/g' /etc/modsecurity/modsecurity.conf || true
  fi

  # Main include file used by nginx module
  as_root mkdir -p /etc/nginx/modsec
  cat <<'EOF' | as_root tee /etc/nginx/modsec/main.conf >/dev/null
Include /etc/modsecurity/modsecurity.conf

# OWASP CRS
Include /usr/share/modsecurity-crs/crs-setup.conf
Include /usr/share/modsecurity-crs/rules/*.conf
EOF

  # Ensure nginx module config exists (Ubuntu usually provides /etc/nginx/modsecurity.conf)
  if [[ ! -f /etc/nginx/modsecurity.conf ]]; then
    cat <<'EOF' | as_root tee /etc/nginx/modsecurity.conf >/dev/null
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
EOF
  else
    # Keep existing file, but ensure it points to our main.conf
    if ! grep -q "/etc/nginx/modsec/main.conf" /etc/nginx/modsecurity.conf; then
      cat <<'EOF' | as_root tee /etc/nginx/modsecurity.conf >/dev/null
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
EOF
    fi
  fi
}

setup_tls_self_signed_if_missing() {
  if [[ -f "${TLS_CERT_PATH}" && -f "${TLS_KEY_PATH}" ]]; then
    return 0
  fi
  as_root mkdir -p "$(dirname "${TLS_CERT_PATH}")"
  as_root mkdir -p "$(dirname "${TLS_KEY_PATH}")"

  # Self-signed cert for demo
  as_root openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${TLS_KEY_PATH}" \
    -out "${TLS_CERT_PATH}" \
    -subj "/CN=sdn-demo" >/dev/null 2>&1
  as_root chmod 600 "${TLS_KEY_PATH}" || true
}

setup_nginx_site() {
  as_root mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

  local modsec_include
  modsec_include=""
  if [[ "${MODSEC_ENABLE}" = "1" && "${_MODSEC_AVAILABLE}" = "1" ]]; then
    modsec_include="include /etc/nginx/modsecurity.conf;"
  fi

  local cf_enforce
  cf_enforce=""
  if [[ "${CLOUDFLARE_MODE}" = "1" && "${CLOUDFLARE_ALLOWLIST_NGINX}" = "1" ]]; then
    cf_enforce='if ($sdn_from_cf = 0) { return 403; }'
  fi

  cat <<EOF | as_root tee /etc/nginx/sites-available/sdn >/dev/null
# sdn Reverse Proxy + WAF

# Per-IP zones
limit_req_zone \$binary_remote_addr zone=sdn_req:10m rate=${NGINX_LIMIT_REQ_RATE};
limit_conn_zone \$binary_remote_addr zone=sdn_conn:10m;

server {
  listen 80 default_server;
  listen [::]:80 default_server;

  # If you prefer to force HTTPS, uncomment the redirect.
  # return 301 https://\$host\$request_uri;

  ${modsec_include}

  ${cf_enforce}

  location / {
    limit_req zone=sdn_req burst=${NGINX_LIMIT_REQ_BURST} nodelay;
    limit_conn sdn_conn ${NGINX_LIMIT_CONN};

    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;

    proxy_connect_timeout 10s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;

    proxy_pass http://${WEB_UPSTREAM_HOST}:${WEB_UPSTREAM_PORT};
  }
}

server {
  listen 443 ssl http2 default_server;
  listen [::]:443 ssl http2 default_server;

  ssl_certificate     ${TLS_CERT_PATH};
  ssl_certificate_key ${TLS_KEY_PATH};

  # Reasonable TLS defaults (demo)
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 10m;
  ssl_protocols TLSv1.2 TLSv1.3;

  ${modsec_include}

  ${cf_enforce}

  location / {
    limit_req zone=sdn_req burst=${NGINX_LIMIT_REQ_BURST} nodelay;
    limit_conn sdn_conn ${NGINX_LIMIT_CONN};

    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;

    proxy_connect_timeout 10s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;

    proxy_pass http://${WEB_UPSTREAM_HOST}:${WEB_UPSTREAM_PORT};
  }
}
EOF

  as_root rm -f /etc/nginx/sites-enabled/default || true
  as_root ln -sf /etc/nginx/sites-available/sdn /etc/nginx/sites-enabled/sdn

  as_root nginx -t
  as_root systemctl enable nginx
  as_root systemctl restart nginx
}

setup_sysctl_limits() {
  cat <<'EOF' | as_root tee /etc/sysctl.d/99-sdn-hardening.conf >/dev/null
# sdn demo hardening (network)
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.ip_local_port_range = 10240 65535

# Enable basic kernel protections
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

  # Apply only our sysctl file to avoid failures from unrelated/unsupported keys on some kernels.
  as_root sysctl -p /etc/sysctl.d/99-sdn-hardening.conf >/dev/null || true

  # Raise file descriptors (nginx + general)
  cat <<'EOF' | as_root tee /etc/security/limits.d/99-sdn-nofile.conf >/dev/null
* soft nofile 65535
* hard nofile 65535
EOF

  # Nginx systemd override (so it can actually use higher nofile)
  as_root mkdir -p /etc/systemd/system/nginx.service.d
  cat <<'EOF' | as_root tee /etc/systemd/system/nginx.service.d/override.conf >/dev/null
[Service]
LimitNOFILE=65535
EOF
  as_root systemctl daemon-reload
  as_root systemctl restart nginx
}

setup_firewall_nftables() {
  local ssh_port
  ssh_port="$(get_ssh_port)"

  as_root systemctl enable nftables

  # Backup existing /etc/nftables.conf before overwriting
  as_root mkdir -p /root/sdn-hardening-backup
  if [[ -f /etc/nftables.conf ]]; then
    as_root cp /etc/nftables.conf /root/sdn-hardening-backup/nftables.prev.conf || true
  fi

  # Backup existing rules
  if as_root nft list ruleset >/dev/null 2>&1; then
    as_root nft list ruleset > /root/sdn-hardening-backup/nftables.ruleset.$(date +%s).bak || true
  fi

  # Apply new ruleset (strict but safe)
  cat <<EOF | as_root tee /etc/nftables.conf >/dev/null
#!/usr/sbin/nft -f
flush ruleset

$(
  if [[ "${CLOUDFLARE_MODE}" = "1" && "${CLOUDFLARE_ALLOWLIST_NFT}" = "1" && -f /etc/sdn/cloudflare/nft_cloudflare_sets.nft ]]; then
    printf '%s\n' "include \"/etc/sdn/cloudflare/nft_cloudflare_sets.nft\""
  fi
)

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Allow loopback
    iif "lo" accept

    # Allow established/related
    ct state established,related accept

    # ICMP for troubleshooting
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    # SSH (detected)
    tcp dport ${ssh_port} accept

    # HTTP/HTTPS with coarse protection on new connections
$(
  if [[ "${FW_EXPOSE_WEB_PORTS}" != "1" ]]; then
    printf '%s\n' "# Web ports are not exposed (FW_EXPOSE_WEB_PORTS=0). Use a tunnel/reverse proxy to reach the UI."
  elif [[ "${CLOUDFLARE_MODE}" = "1" && "${CLOUDFLARE_ALLOWLIST_NFT}" = "1" && -f /etc/sdn/cloudflare/nft_cloudflare_sets.nft ]]; then
    printf '%s\n' "ip saddr \$CF4 tcp dport { 80, 443 } ct state new limit rate ${FW_HTTP_NEW_CONN_RATE} burst ${FW_HTTP_NEW_CONN_BURST} packets accept"
    printf '%s\n' "ip6 saddr \$CF6 tcp dport { 80, 443 } ct state new limit rate ${FW_HTTP_NEW_CONN_RATE} burst ${FW_HTTP_NEW_CONN_BURST} packets accept"
    printf '%s\n' "tcp dport { 80, 443 } ct state established,related accept"
  else
    printf '%s\n' "tcp dport { 80, 443 } ct state new limit rate ${FW_HTTP_NEW_CONN_RATE} burst ${FW_HTTP_NEW_CONN_BURST} packets accept"
    printf '%s\n' "tcp dport { 80, 443 } ct state established,related accept"
  fi
)

    # Drop everything else inbound by default
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF

  # Safety rollback: schedule revert in 2 minutes unless user cancels.
  # We implement by storing a revert script; user can cancel by deleting it.
  cat <<'EOF' | as_root tee /root/sdn-hardening-backup/revert_firewall.sh >/dev/null
#!/usr/bin/env bash
set -euo pipefail
if [[ -f /root/sdn-hardening-backup/nftables.prev.conf ]]; then
  cp /root/sdn-hardening-backup/nftables.prev.conf /etc/nftables.conf
  systemctl restart nftables || true
fi
EOF
  as_root chmod +x /root/sdn-hardening-backup/revert_firewall.sh || true

  # Sentinel file: if it still exists after 120s, we rollback.
  as_root touch /root/sdn-hardening-backup/rollback.pending
  as_root nohup bash -lc 'sleep 120; if [[ -f /root/sdn-hardening-backup/rollback.pending ]]; then /root/sdn-hardening-backup/revert_firewall.sh; fi' >/dev/null 2>&1 &

  # Start/apply
  # Load rules explicitly to avoid cases where the service restarts but doesn't load our config.
  if ! as_root nft -f /etc/nftables.conf >/dev/null 2>&1; then
    echo "[!] Failed to load nftables rules from /etc/nftables.conf" >&2
    echo "[!] Keeping rollback timer active. Check /etc/nftables.conf syntax and rerun." >&2
    as_root systemctl restart nftables || true
    return 1
  fi

  as_root systemctl restart nftables

  # Verify that the active ruleset is strict (input policy drop). If not, warn loudly.
  if ! as_root nft list ruleset 2>/dev/null | grep -q "policy drop"; then
    echo "[!] WARNING: nftables ruleset appears NOT to be in 'drop by default' mode." >&2
    echo "[!] This means ports like 8080 may be exposed. Investigate nftables.service and /etc/nftables.conf." >&2
    echo "[!] Keeping rollback timer active. If you confirm SSH+web OK, you may still remove rollback.pending." >&2
  fi
}

print_next_steps() {
  echo ""
  echo "[+] Hardening applied."
  echo "[!] IMPORTANT: Confirm you still have SSH and web access, then run:"
  echo "    sudo rm -f /root/sdn-hardening-backup/rollback.pending"
  echo "    (If you don't remove it, firewall will auto-rollback after 120s.)"
  echo "[i] Next steps to run your sdn services behind Nginx:"
  echo "    1) Start services normally: ./scripts/sdn_lab.sh start"
  echo "    2) Access UI via: http://<SERVER_IP>/  (or https://<SERVER_IP>/ using self-signed cert)"
  echo ""
  echo "[i] IMPORTANT: Ensure webapp binds to 127.0.0.1 (APP_HOST=127.0.0.1) and TRUST_PROXY_HEADERS=1 so rate limiting uses real client IP behind Nginx."
  if [[ "${CLOUDFLARE_MODE}" = "1" ]]; then
    echo "[i] Cloudflare mode is ENABLED. Ensure DNS is proxied (orange cloud) before enabling firewall allowlist to avoid locking yourself out of 80/443."
    echo "[i] Cloudflare allowlist: NGINX=${CLOUDFLARE_ALLOWLIST_NGINX} NFT=${CLOUDFLARE_ALLOWLIST_NFT}"
  fi
  if [[ "${FW_EXPOSE_WEB_PORTS}" != "1" ]]; then
    echo "[i] Web ports 80/443 are CLOSED by firewall (FW_EXPOSE_WEB_PORTS=0)."
    echo "[i] Use a tunnel to reach the UI (example Cloudflare Quick Tunnel):"
    echo "    cloudflared tunnel --url http://127.0.0.1:${WEB_UPSTREAM_PORT}"
  fi
}

main() {
  echo "[+] sdn hardening (Ubuntu 22.04) starting..."
  ensure_packages
  setup_modsecurity
  setup_cloudflare_files
  setup_tls_self_signed_if_missing
  setup_nginx_site
  setup_sysctl_limits
  if [[ "${FW_ENABLE}" = "1" ]]; then
    setup_firewall_nftables
  else
    echo "[i] Firewall setup skipped (FW_ENABLE=0)"
  fi
  print_next_steps
}

main "$@"
