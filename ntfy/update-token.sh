#!/bin/sh
#
# ntfy Token Rotation Script
#
# Purpose: Find and replace an old ntfy token with a new one across:
#   - Files in $HOME and /etc
#   - Current user's crontab
#   - Root crontab and system cron files (if running as root)
#
# Usage:
#   sh update-token.sh "tk_old_token_here" "tk_new_token_here"
#
# As regular user:
#   sh update-token.sh "tk_abc123old" "tk_xyz789new"
#
# As root (to also update root cron and /etc/cron.d):
#   sudo sh update-token.sh "tk_abc123old" "tk_xyz789new"
#
# Notes:
#   - Creates .bak backups of all modified files
#   - Skips binary files and excluded directories
#   - Safe to run multiple times (idempotent)
#

set -eu

OLD="$1"
NEW="$2"

# Directories/files to scan
SEARCH_PATHS="
$HOME
/etc
"

# Directories to exclude (add/remove as needed)
EXCLUDES="
$HOME/.cache
$HOME/.bash_history
$HOME/.local/share/Trash
/var/lib/docker
"

# Replace tokens in files under SEARCH_PATHS
for p in $SEARCH_PATHS; do
    [ -d "$p" ] || continue

    # Build find command with proper -prune exclusions
    find_cmd="find \"$p\""

    # Add exclusions
    first=1
    for exclude in $EXCLUDES; do
        if [ "$first" -eq 1 ]; then
            find_cmd="$find_cmd \\( -path \"$exclude\" -o -path \"$exclude/*\""
            first=0
        else
            find_cmd="$find_cmd -o -path \"$exclude\" -o -path \"$exclude/*\""
        fi
    done

    if [ "$first" -eq 0 ]; then
        find_cmd="$find_cmd \\) -prune -o"
    fi

    find_cmd="$find_cmd -type f ! -path '*/.git/*' -print"

    # Execute find and process files
    eval "$find_cmd" | while IFS= read -r f; do
        # Skip binary files; only edit files containing OLD token
        if grep -Iq "$OLD" "$f" 2>/dev/null && grep -q "$OLD" "$f" 2>/dev/null; then
            sed -i.bak "s/$OLD/$NEW/g" "$f"
            printf 'Updated %s\n' "$f"
        fi
    done
done

# Update current user's crontab
if crontab -l >/dev/null 2>&1; then
    crontab -l | sed "s/$OLD/$NEW/g" | crontab -
    printf 'Updated crontab for %s\n' "$(id -un)"
fi

# Update root crontab and system cron files (only if running as root)
if [ "$(id -u)" -eq 0 ]; then
    # Root's personal crontab
    if crontab -l -u root >/dev/null 2>&1; then
        crontab -l -u root | sed "s/$OLD/$NEW/g" | crontab -u root -
        printf 'Updated root crontab\n'
    fi

    # System /etc/crontab
    if [ -f /etc/crontab ]; then
        sed -i.bak "s/$OLD/$NEW/g" /etc/crontab
        printf 'Updated /etc/crontab\n'
    fi

    # System cron drop-in directory
    if [ -d /etc/cron.d ]; then
        find /etc/cron.d -type f -exec sed -i.bak "s/$OLD/$NEW/g" {} + 2>/dev/null
        printf 'Updated /etc/cron.d files\n'
    fi
fi

printf '\nToken rotation complete. Review .bak files if needed.\n'
