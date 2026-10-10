#!/usr/bin/env bash
# Puts the node of calls on one server, by ssh, from dist/ (make release
# first). The server gets the user vcall, /opt/vcall/{bin,etc,data}, the
# unit, the firewall rules and a running node; a rerun replaces the binary
# and restarts. The key and the TURN secret in /opt/vcall/data stay, so the
# node keeps its id.
#
#   scripts/deploy-node.sh root@HOST PUBLIC_IP [CONTROL_PORT] [RELAY_PORTS]
#
# Ports: CONTROL_PORT tcp, 3478 udp+tcp (STUN/TURN), 3479 udp+tcp (SFU) and the
# relay range udp are opened in ufw.
#
# CONTROL_PORT is 443 by default; on a server where nginx holds 443, name
# another (the project's servers use 8443). RELAY_PORTS is first-last, the
# UDP ports relayed traffic leaves by (49152-49999 by default: 848 ports,
# one per allocation). SSH options come from the environment: SSH_OPTS,
# e.g. "-i key -o UserKnownHostsFile=known_hosts".
set -euo pipefail

host="${1:?user@host}"
public_ip="${2:?the public IP of the server}"
port="${3:-443}"
relay="${4:-49152-49999}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ssh_opts="${SSH_OPTS:-}"

[ -x "$here/dist/vcall" ] || { echo "no dist/vcall: run make release first" >&2; exit 1; }

# shellcheck disable=SC2086
scp -q $ssh_opts "$here/dist/vcall" "$here/deploy/vcall.service" "$host:/tmp/"
# shellcheck disable=SC2086
ssh $ssh_opts "$host" "set -e
id vcall >/dev/null 2>&1 || useradd --system --home /opt/vcall --shell /usr/sbin/nologin vcall
mkdir -p /opt/vcall/bin /opt/vcall/etc /opt/vcall/data
install -m755 /tmp/vcall /opt/vcall/bin/vcall
if [ ! -f /opt/vcall/etc/vcall.env ]; then
  printf 'VCALL_LISTEN=0.0.0.0:%s\nVCALL_PUBLIC_IP=%s\nVCALL_RELAY_PORTS=%s\nVCALL_LOG=info\n' '$port' '$public_ip' '$relay' > /opt/vcall/etc/vcall.env
fi
chown root:vcall /opt/vcall/etc/vcall.env; chmod 640 /opt/vcall/etc/vcall.env
chown -R vcall:vcall /opt/vcall/data; chmod 750 /opt/vcall/data
install -m644 /tmp/vcall.service /etc/systemd/system/vcall.service
rm -f /tmp/vcall /tmp/vcall.service
if command -v ufw >/dev/null 2>&1; then
  ufw allow '$port'/tcp >/dev/null
  ufw allow 3478/udp >/dev/null
  ufw allow 3478/tcp >/dev/null
  ufw allow 3479/udp >/dev/null
  ufw allow 3479/tcp >/dev/null
  ufw allow '${relay/-/:}'/udp >/dev/null
fi
# The SFU socket asks for 4 MiB buffers; the kernel caps them at wmem_max/rmem_max (212992 by default).
printf 'net.core.rmem_max=4194304\nnet.core.wmem_max=4194304\n' > /etc/sysctl.d/90-vcall.conf
sysctl -q -p /etc/sysctl.d/90-vcall.conf
systemctl daemon-reload
systemctl enable vcall >/dev/null 2>&1
systemctl restart vcall
sleep 2
systemctl is-active vcall
echo \"ref: \$(sudo -u vcall /opt/vcall/bin/vcall id --data /opt/vcall/data --addr '$public_ip:$port')\"
/opt/vcall/bin/vcall ctl --socket /run/vcall/ctl.sock health
"
