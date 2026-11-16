#!/bin/bash
# logging.sh — Blue Team 1: make logs survive and watch the files Red Team likes to touch.
# Run as root on each Linux host.
#  - journald: persistent storage (survives reboot / a wiped /run)
#  - auditd: if installed, watch identity, sudoers, ssh, cron and PAM files
# Rulebook: Red Team may not delete all logging, so these give you evidence to investigate.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
LOG=/var/log/bt1_hardening.log
log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }

# --- journald persistent ---
mkdir -p /var/log/journal /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/00-bt1.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=1G
EOF
systemctl restart systemd-journald
journalctl --flush 2>/dev/null || true
log "journald set to persistent storage"

# --- auditd (only if already installed) ---
if command -v auditctl >/dev/null 2>&1; then
  RULES=/etc/audit/rules.d/99-bt1.rules
  : > "$RULES"
  while IFS='|' read -r path key; do
    [[ -e "$path" ]] && echo "-w $path -p wa -k $key" >> "$RULES"
  done <<'EOF'
/etc/passwd|identity
/etc/shadow|identity
/etc/group|identity
/etc/sudoers|sudoers
/etc/sudoers.d|sudoers
/etc/ssh/sshd_config|sshd
/etc/ssh/sshd_config.d|sshd
/root/.ssh|ssh_keys
/etc/crontab|cron
/etc/cron.d|cron
/var/spool/cron|cron
/etc/pam.d|pam
/etc/systemd/system|systemd
EOF
  systemctl enable --now auditd 2>/dev/null || true
  augenrules --load >/dev/null 2>&1 || auditctl -R "$RULES" >/dev/null 2>&1 || true
  log "auditd rules loaded from $RULES"
  echo "Search examples:  ausearch -k identity -ts today    ausearch -k ssh_keys -ts today"
else
  echo "auditd is not installed. 'apt install auditd' only works if the package mirror is"
  echo "reachable from the competition network; otherwise rely on journald + 02_find_persistence.sh."
fi

echo
echo "SSH logins are in the journal:  journalctl -u ssh --since today"
