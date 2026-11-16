#!/bin/bash
# doghouse_harden.sh — run as root on Doghouse (192.168.1.5)
set -euo pipefail

# 1) Host: SSH hygiene (don't disable SSH — Rule 15)
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Keep password auth ON unless scoring engine uses keys — verify first.
systemctl reload ssh

# 2) Host firewall: individual rules only, no subnet blocks (Rule 16)
# Allow SSH + Docker-published Apache port (confirm actual port first: docker ps)
ufw allow 22/tcp
# ufw allow 80/tcp   # uncomment ONLY if Apache is published on 80
ufw --force enable

# 3) Audit Docker exposure — don't change mappings, just document
docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Image}}' | tee /root/docker_audit.txt

# 4) Container-side Apache hardening (no topology change)
# Find the Apache container name from the audit, then:
# docker exec <container> bash -c '
#   a2enmod headers >/dev/null
#   echo "ServerTokens Prod" >> /etc/apache2/conf-enabled/security.conf
#   echo "ServerSignature Off" >> /etc/apache2/conf-enabled/security.conf
#   apachectl -k graceful'
# (Left commented so you paste the real container name.)

echo "Doghouse host hardening done. Review /root/docker_audit.txt"
