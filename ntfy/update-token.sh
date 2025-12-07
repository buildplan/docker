#!/bin/sh
# Usage:
#   sh update-token.sh "tk_old_token_here" "tk_new_token_here"

set -eu

OLD="$1"
NEW="$2"

# Directories/files to scan
SEARCH_PATHS="
$HOME
/etc
"

# Directories to exclude (absolute paths)
# Add/remove entries as needed
EXCLUDES="
$HOME/.cache
$HOME/.local/share/Trash
/var/lib/docker
/home/ali/forgejo
"

# Build the find(1) -path ... -prune expression from EXCLUDES
build_prune_expr() {
    for d in $EXCLUDES; do
        # Each dir excluded as dir itself and everything under it
        printf ' -path %s -o -path %s -o' "$d" "$d/*"
    done
}

for p in $SEARCH_PATHS; do
    [ -d "$p" ] || continue

    # shellcheck disable=SC2046
    find "$p" \
        \( $(build_prune_expr | sed 's/ -o$//') \) -prune -o \
        -type f ! -path '*/.git/*' -print |
    while IFS= read -r f; do
        # Skip binary-ish files and only touch files that contain OLD
        if grep -Iq "$OLD" "$f" 2>/dev/null && grep -q "$OLD" "$f" 2>/dev/null; then
            sed -i.bak "s/$OLD/$NEW/g" "$f"
            printf 'Updated %s\n' "$f"
        fi
    done
done

# Update user crontab (for current user)
if crontab -l >/dev/null 2>&1; then
    crontab -l | sed "s/$OLD/$NEW/g" | crontab -
    printf 'Updated crontab for %s\n' "$(id -un)"
fi
