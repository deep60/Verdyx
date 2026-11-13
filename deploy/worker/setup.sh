#!/usr/bin/env bash
# One-time setup of the Verdyx worker on a fresh Oracle Ubuntu (arm64) VM.
#
#   sudo bash setup.sh <WORKER_PRIVATE_IP> <MAIN_PRIVATE_IP>
#
# Installs Docker, writes /opt/verdyx-worker (compose file and .env with a new
# ML token), and limits ClamAV (3310) and the ML service (8090) to the main VM.
# Safe to run again: it keeps an existing .env and replaces its own firewall
# rules. Start the services afterwards with the command it prints.
set -euo pipefail

worker_ip="${1:?usage: sudo bash setup.sh <WORKER_PRIVATE_IP> <MAIN_PRIVATE_IP>}"
main_ip="${2:?usage: sudo bash setup.sh <WORKER_PRIVATE_IP> <MAIN_PRIVATE_IP>}"
here="$(cd "$(dirname "$0")" && pwd)"
dest=/opt/verdyx-worker

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo." >&2
  exit 1
fi
if ! ip -4 addr show | grep -q "inet ${worker_ip}/"; then
  echo "${worker_ip} is not an address of this machine. Use the private IP from" >&2
  echo "Instance details -> Primary VNIC -> Private IPv4 address." >&2
  exit 1
fi

echo "== Docker"
if ! command -v docker >/dev/null; then
  apt-get update -q
  apt-get install -yq ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -yq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
systemctl enable --now docker
if [[ -n "${SUDO_USER:-}" ]]; then usermod -aG docker "$SUDO_USER"; fi

echo "== Files in $dest"
mkdir -p "$dest/ml-models/pe"
install -m 0644 "$here/docker-compose.yml" "$dest/docker-compose.yml"
if [[ ! -f "$dest/.env" ]]; then
  token="$(openssl rand -hex 32)"
  sed -e "s|^WORKER_PRIVATE_IP=.*|WORKER_PRIVATE_IP=${worker_ip}|" \
      -e "s|^MAIN_PRIVATE_IP=.*|MAIN_PRIVATE_IP=${main_ip}|" \
      -e "s|^ML_SERVICE_TOKEN=.*|ML_SERVICE_TOKEN=${token}|" \
      "$here/.env.example" > "$dest/.env"
  chmod 600 "$dest/.env"
  echo "   wrote $dest/.env with a new ML_SERVICE_TOKEN"
else
  echo "   keeping the existing $dest/.env"
fi

echo "== Firewall: only ${main_ip} may reach 3310 and 8090"
# Docker-published ports bypass INPUT, so filter them in DOCKER-USER (which
# sees the container port after DNAT). Drop our old rules first so re-runs
# don't stack them.
iptables -N DOCKER-USER 2>/dev/null || true
while iptables -D DOCKER-USER -p tcp -m multiport --dports 3310,8090 -m comment --comment verdyx-worker -j DROP 2>/dev/null; do :; done
while iptables -S DOCKER-USER | grep -q 'verdyx-worker-allow'; do
  rule="$(iptables -S DOCKER-USER | grep 'verdyx-worker-allow' | head -1 | sed 's/^-A/-D/')"
  eval "iptables $rule"
done
iptables -I DOCKER-USER 1 -p tcp -m multiport --dports 3310,8090 -m comment --comment verdyx-worker -j DROP
iptables -I DOCKER-USER 1 -p tcp -s "$main_ip" -m multiport --dports 3310,8090 -m comment --comment verdyx-worker-allow -j ACCEPT
iptables -I DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment verdyx-worker-allow -j ACCEPT
if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null; fi

echo "== Swap (helps while clamd reloads its database)"
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

cat <<EOF

Done. Next:
  1. Copy the model bundle into $dest/ml-models/pe
     (model.txt, calibration.json, bundle.json, report.md).
  2. Start:   cd $dest && sudo docker compose up -d
  3. On the MAIN VM, add to /opt/verdyx/.env:
       ENABLE_CLAMAV=true
       CLAMAV_HOST=${worker_ip}:3310
       PE_MODEL_URL=http://${worker_ip}:8090
       ML_SERVICE_TOKEN=<the value in $dest/.env>
     then: cd /opt/verdyx && sudo docker compose -f docker-compose.gcp.yml up -d --force-recreate --no-deps analysis-engine
EOF
