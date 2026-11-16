#!/bin/bash
# passwd.sh -- Blue Team (Charlie Brown Gang)
#Usage: ./passwd.sh <password_file>
# password_file format: username:newpassword (one per line)
# Delete file after use

set -euo pipefail

ADMINS=(charliebrown lucy vaanpelt linusvanpelt peppermintpatty marcie)
NORMALS=(snoopy woodstock sallybrown schroeder pigpen)
GRAY=(grayteam othergrayteam violetgray)

AUDIT=/var/log/bt1_password_rotation.log

if [[ $EUID -ne 0 ]]; then echo "Run as root"; exit 1; fi
if [[ $# -ne 1 || ! -r "$1" ]]; then echo "Usage: $0 <password_file>"; exit 1; fiif [[ $# -ne 1 || ! -r "$1" ]]; then echo "Usage: $0 <password_file>"; exit 1; fi

for g in "${GRAY[@]}"; do
  if grep -q "^${g}:" "$1"; then
    echo "REFUSING: password file contains Gray Team account '$g'"; exit 2
  fi
done

echo "=== Rotation started $(date -Is) ===" | tee -a "$AUDIT"

while IFS=: read -r user pass; do
    [[ -z "$user" || -z "$pass" ]] && continue
    if ! id "$user" &>/dev/null; then
     echo "SKIP: $user does not exist locally" | tee -a "$AUDIT"; continue
    fi
    # Skip Gray Team defensively
    for g in "${GRAY[@]}"; do [[ "$user" == "$g" ]] && { echo "SKIP Gray: $user" | tee -a "$AUDIT"; continue 2; }; done


echo "$user:$pass" | chpasswd
  # Do NOT force expiry on service accounts; only nudge humans
  if [[ " ${NORMALS[*]} " == *" $user "* ]]; then
    # Optional: force change at next login for normal users only.
    # Comment this out if the scoring engine uses these accounts.
    # chage -d 0 "$user"
    :
  fi
  echo "ROTATED: $user @ $(date -Is)" | tee -a "$AUDIT"
done < "$1"

echo "=== Rotation complete $(date -Is) ===" | tee -a "$AUDIT"