#!/bin/bash
# change_passwd.sh — Blue Team 1
# Changes the password of the 5 admin and 5 normal accounts below, and nothing else.
# Anything else in the password file (Gray Team, root, typos) is ignored.
# Usage: sudo ./change_passwd.sh new_passwords.txt      (file lines: username:password)

ACCOUNTS=(charliebrown lucyvanpelt linusvanpelt peppermintpatty marcie snoopy woodstock sallybrown schroeder pigpen)

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
[[ $# -eq 1 && -r "$1" ]] || { echo "Usage: $0 <password_file>"; exit 1; }

for user in "${ACCOUNTS[@]}"; do
  line=$(grep -m1 "^${user}:" "$1") || { echo "SKIP $user: not in the file"; continue; }
  pass=${line#*:}
  pass=${pass%$'\r'}
  id "$user" &>/dev/null || { echo "SKIP $user: no such user on this host"; continue; }
  if [[ -z "$pass" || "$pass" == CHANGE_ME* ]]; then
    echo "SKIP $user: empty or placeholder password"; continue
  fi
  if printf '%s:%s\n' "$user" "$pass" | chpasswd; then
    echo "OK   $user"
  else
    echo "FAIL $user"
  fi
done
