#!/bin/bash
# backup.sh — Blue Team 1: snapshot configs + this host's scored-service data so you can
# recover from a Red Team break (rule 23 says every break must be recoverable; this is how).
#
# Usage: sudo ./07_backup.sh <mysql|smtp|apache|samba> [--golden] [--quiet]
#   mysql  -> KiteTree    smtp -> ToyPiano    apache -> Doghouse (Docker)    samba -> Snowman
#   --golden  store a never-rotated snapshot in /root/bt1_backups/golden. Take one while the
#             box is known-good, BEFORE Red Team has had time to touch it.
#   --quiet   minimal output (for cron)
#
# Regular snapshots go to /root/bt1_backups/data/<role>-<timestamp>/ (newest 8 kept).
# Copy at least one snapshot OFF the host (jumpbox): Red Team can delete /root on a rooted box.
set -euo pipefail

USAGE="Usage: $0 <mysql|smtp|apache|samba> [--golden] [--quiet]"
ROLE=${1:-}
case "$ROLE" in mysql|smtp|apache|samba) ;; *) echo "$USAGE"; exit 1 ;; esac
shift
GOLDEN=0
QUIET=0
for a in "$@"; do
  case "$a" in
    --golden) GOLDEN=1 ;;
    --quiet)  QUIET=1 ;;
    *) echo "$USAGE"; exit 1 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }

ROOT=/root/bt1_backups
LOG=/var/log/bt1_hardening.log
STAMP=$(date +%Y%m%d-%H%M%S)
if [[ $GOLDEN -eq 1 ]]; then DEST=$ROOT/golden/$ROLE-$STAMP; else DEST=$ROOT/data/$ROLE-$STAMP; fi

say()  { [[ $QUIET -eq 1 ]] || echo "$*"; }
warn() { echo "WARN: $*" | tee -a "$LOG" >&2; }
safe_tar() {  # tar exit 1 = "a file changed while reading", which is acceptable
  local rc=0
  tar --warning=no-file-changed "$@" || rc=$?
  [[ $rc -le 1 ]]
}
too_big() {   # skip anything over 500 MB so a backup can never fill the disk
  local sz
  sz=$(du -sm "$1" 2>/dev/null | cut -f1)
  [[ ${sz:-0} -gt 500 ]]
}

# A full disk can break scored services, so refuse to run when space is low.
avail_kb=$(df --output=avail -k /root | tail -1 | tr -d ' ')
if (( avail_kb < 1048576 )); then
  echo "REFUSING: under 1 GB free on /root; a full disk can break scored services."
  exit 2
fi

umask 077
mkdir -p "$DEST"

# ---- 1. system files ---------------------------------------------------------
say "[1/4] system files"
# /etc, /home, /root: everything except caches and single files over 50 MB (listed in
# skipped-large-files.txt). Software dirs (/usr/local /opt /srv) are skipped entirely if over
# 500 MB, since reinstalling beats archiving them. BT1_BASE_PATHS overrides the first group (testing).
read -ra BASE_PATHS <<< "${BT1_BASE_PATHS:-/etc /home /root}"
PATHS=()
for d in "${BASE_PATHS[@]}"; do
  [[ -e $d ]] && PATHS+=("$d")
done
for d in /var/spool/cron /usr/local /opt /srv; do
  [[ -e $d ]] || continue
  if too_big "$d"; then warn "skipping $d (over 500 MB)"; continue; fi
  PATHS+=("$d")
done
PRUNE=( \( -path /root/bt1_backups -o -name .cache \) -prune -o )
{ find "${PATHS[@]}" -xdev "${PRUNE[@]}" \( -type d -o -type l -o -type f -size -50M \) -print0 2>/dev/null || true; } \
  | safe_tar -czpf "$DEST/system.tar.gz" --null --no-recursion -T - 2>/dev/null \
  || { echo "system tar failed"; exit 3; }
find "${PATHS[@]}" -xdev "${PRUNE[@]}" -type f -size +50M -print 2>/dev/null > "$DEST/skipped-large-files.txt" || true
[[ -s "$DEST/skipped-large-files.txt" ]] && warn "$(wc -l < "$DEST/skipped-large-files.txt") file(s) over 50 MB not archived (see skipped-large-files.txt)"

# ---- 2. system state (for diffing later) ---------------------------------------
say "[2/4] system state"
{
  echo "# $(hostname) $(date -Is)"
  echo "## listening";     ss -tulpn
  echo "## accounts";      getent passwd
  echo "## sudo group";    getent group sudo
  echo "## enabled units"; systemctl list-unit-files --state=enabled --no-pager
  echo "## packages";      dpkg --get-selections
  echo "## firewall";      ufw status verbose 2>&1 || true
  iptables-save 2>&1 || true
} > "$DEST/state.txt" 2>&1 || true

# ---- 3. role-specific data -------------------------------------------------------
say "[3/4] role data ($ROLE)"
case "$ROLE" in
  mysql)
    if command -v mysqldump >/dev/null 2>&1; then
      if mysqldump --all-databases --single-transaction --routines --events --triggers \
           > "$DEST/mysql-all.sql" 2> "$DEST/mysqldump.err"; then
        say "      mysql dump OK ($(du -h "$DEST/mysql-all.sql" | cut -f1))"
      else
        warn "mysqldump failed (see $DEST/mysqldump.err). If root has a password, put it in /root/.my.cnf (chmod 600) and re-run."
      fi
    else
      warn "mysqldump not found"
    fi
    ;;

  smtp)
    ss -ltnp 2>/dev/null | grep -E ':(25|465|587)\s' > "$DEST/smtp-listeners.txt" || true
    command -v postconf >/dev/null 2>&1 && { postconf -n > "$DEST/postfix-effective.txt" 2>&1 || true; }
    MAILPATHS=()
    for d in /etc/postfix /etc/exim4 /etc/dovecot /etc/opendkim /etc/aliases /etc/aliases.db /etc/mailname /var/mail; do
      [[ -e $d ]] && MAILPATHS+=("$d")
    done
    if [[ ${#MAILPATHS[@]} -gt 0 ]]; then
      safe_tar -czpf "$DEST/mail.tar.gz" "${MAILPATHS[@]}" 2>/dev/null || warn "mail tar failed"
    else
      warn "no mail config directories found"
    fi
    ;;

  apache)
    if command -v docker >/dev/null 2>&1; then
      docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' > "$DEST/containers.txt" 2>&1 || true
      mkdir -p "$DEST/inspect"
      for c in $(docker ps -aq); do
        n=$(docker inspect -f '{{.Name}}' "$c" | tr -d /)
        docker inspect "$c" > "$DEST/inspect/$n.json" 2>/dev/null || true
        if [[ $GOLDEN -eq 1 ]]; then
          # Local image of the container's current filesystem: fast recovery if it gets trashed.
          docker commit "$c" "bt1-backup/$n:$STAMP" >/dev/null 2>&1 \
            && echo "bt1-backup/$n:$STAMP" >> "$DEST/committed-images.txt" || true
        fi
      done
      docker ps -aq | xargs -r docker inspect --format '{{range .Mounts}}{{.Type}} {{.Source}}{{"\n"}}{{end}}' \
        | sort -u | awk 'NF==2' > "$DEST/mounts.txt" || true
      i=0
      while read -r type src; do
        [[ "$type" == bind || "$type" == volume ]] || continue
        [[ -e "$src" && "$src" != "/" && "$src" != /var/run/docker.sock ]] || continue
        if too_big "$src"; then warn "skipping $src (over 500 MB)"; continue; fi
        i=$((i + 1))
        safe_tar -czpf "$DEST/mount-$i.tar.gz" "$src" 2>/dev/null || warn "tar of $src failed"
        echo "mount-$i.tar.gz <- $src" >> "$DEST/mounts-index.txt"
      done < "$DEST/mounts.txt"
      find /root /home /opt /srv /etc /var/www -maxdepth 4 \
        \( -name 'docker-compose*.y*ml' -o -name 'compose.y*ml' -o -name Dockerfile \) 2>/dev/null \
        > "$DEST/compose-files.txt" || true
    else
      warn "docker not found; backing up host web files only"
    fi
    HOSTWEB=()
    for d in /etc/apache2 /var/www; do [[ -e $d ]] && HOSTWEB+=("$d"); done
    if [[ ${#HOSTWEB[@]} -gt 0 ]]; then
      safe_tar -czpf "$DEST/hostweb.tar.gz" "${HOSTWEB[@]}" 2>/dev/null || warn "host web tar failed"
    fi
    ;;

  samba)
    if command -v testparm >/dev/null 2>&1; then
      testparm -s > "$DEST/smb-effective.conf" 2>/dev/null || true
      i=0
      while read -r p; do
        [[ -d "$p" ]] || continue
        if too_big "$p"; then warn "skipping share $p (over 500 MB)"; continue; fi
        i=$((i + 1))
        safe_tar -czpf "$DEST/share-$i.tar.gz" "$p" 2>/dev/null || warn "tar of $p failed"
        echo "share-$i.tar.gz <- $p" >> "$DEST/shares-index.txt"
      done < <(awk '/^[ \t]*path[ \t]*=/ {sub(/^[^=]*=[ \t]*/, ""); print}' "$DEST/smb-effective.conf")
    else
      warn "testparm not found"
    fi
    [[ -d /var/lib/samba ]] && { safe_tar -czpf "$DEST/samba-state.tar.gz" /var/lib/samba 2>/dev/null || warn "samba state tar failed"; }
    pdbedit -L > "$DEST/samba-users.txt" 2>&1 || true
    ;;
esac

# ---- 4. checksums + rotation -----------------------------------------------------
say "[4/4] checksums"
( cd "$DEST" && find . -type f ! -name SHA256SUMS -exec sha256sum {} + > SHA256SUMS )
chmod -R go-rwx "$DEST"

if [[ $GOLDEN -eq 0 ]]; then
  ls -1dt "$ROOT/data/$ROLE"-* 2>/dev/null | tail -n +9 | xargs -r rm -rf --
fi

echo "[$(date -Is)] backup $DEST (role=$ROLE golden=$GOLDEN)" >> "$LOG"
say
say "Backup saved: $DEST ($(du -sh "$DEST" | cut -f1))"
say "Copy it off-host, e.g. from the jumpbox:  scp -r root@<this-host>:$DEST ./"
say "Restore a piece with:  ./08_restore.sh $DEST --list"
