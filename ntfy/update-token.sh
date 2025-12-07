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

# 1) Replace in regular files under the search paths
for p in $SEARCH_PATHS; do
    [ -d "$p" ] || continue
    find "$p" -type f ! -path '*/.git/*' -exec sh -c '
        OLD="$1"; NEW="$2"; f="$3"
        # Skip binary-ish files (crude check)
        if grep -q "$OLD" "$f" 2>/dev/null; then
            sed -i.bak "s/$OLD/$NEW/g" "$f"
            echo "Updated $f"
        fi
    ' sh "$OLD" "$NEW" {} \;
done

# 2) Update user crontab (for current user)
if crontab -l >/dev/null 2>&1; then
    crontab -l | sed "s/$OLD/$NEW/g" | crontab -
    echo "Updated crontab for $(id -un)"
fi
