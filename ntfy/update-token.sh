#!/bin/sh

# run it with:
# sh update-token.sh "tk_old_token_here" "tk_new_token_here"

set -eu

OLD="$1"
NEW="$2"

# Directories/files to scan
SEARCH_PATHS="
$HOME
/etc
"

# Directories to exclude (absolute paths or prefixes)
EXCLUDES="
$HOME/.cache
$HOME/.local/share/Trash
/var/lib/docker
"

is_excluded() {
    p="$1"
    for e in $EXCLUDES; do
        case "$p" in
            "$e"/*|"$e") return 0 ;;
        esac
    done
    return 1
}

for p in $SEARCH_PATHS; do
    [ -d "$p" ] || continue
    if is_excluded "$p"; then
        continue
    fi
    find "$p" -type d | while IFS= read -r d; do
        if is_excluded "$d"; then
            continue
        fi
        find "$d" -maxdepth 1 -type f ! -path '*/.git/*' | while IFS= read -r f; do
            if grep -q "$OLD" "$f" 2>/dev/null; then
                sed -i.bak "s/$OLD/$NEW/g" "$f"
                echo "Updated $f"
            fi
        done
    done
done

# Update user crontab (for current user)
if crontab -l >/dev/null 2>&1; then
    crontab -l | sed "s/$OLD/$NEW/g" | crontab -
    echo "Updated crontab for $(id -un)"
fi
