#!/bin/sh
set -eu

SCRIPT_NAME=$(basename "$0")

print_help() {
    # Colored section titles
    printf '\033[1m\033[36m%s\033[0m\n' "Usage:"
    printf '%s\n' "  ./$SCRIPT_NAME [up|down|restart] [DIR1 DIR2 ...]"
    printf '%s\n' "  ./$SCRIPT_NAME -h | --help"
    printf '\n'

    printf '\033[1m\033[36m%s\033[0m\n' "Description:"
    cat <<'EOF'
  Run 'docker compose' (up/down/restart) in one or more directories.
  Each target directory may have multiple compose files, including:
    - docker-compose.yml / docker-compose.yaml
    - compose.yml / compose.yaml
    - docker-compose-*.yml / docker-compose-*.yaml
    - compose-*.yml / compose-*.yaml

  All detected files in a directory are passed with multiple -f flags.

EOF

    printf '\033[1m\033[36m%s\033[0m\n' "Arguments:"
    cat <<EOF
  up|down|restart    Action to perform.
  DIR1 DIR2 ...      Optional explicit directories. If omitted, you will be
                     prompted for a base directory and exclusions.

EOF

    printf '\033[1m\033[36m%s\033[0m\n' "Examples:"
    printf '%s\n' "  ./$SCRIPT_NAME up"
    printf '%s\n' "  ./$SCRIPT_NAME down dir1 dir2"
    printf '%s\n' "  ./$SCRIPT_NAME restart"
    printf '%s\n' "  ./$SCRIPT_NAME --help"
}

# Handle arguments or prompt if empty (Wizard Mode)
if [ "$#" -gt 0 ]; then
    case "$1" in
        -h|--help)
            print_help
            exit 0
            ;;
    esac

    ACTION="$1"
    shift
else
    # No arguments provided: strict interactive setup
    printf "Select action (up/down/restart): "
    if ! IFS= read -r ACTION; then
        exit 1
    fi

    if [ -z "$ACTION" ]; then
        print_help
        exit 1
    fi
fi

case "$ACTION" in
    up|down|restart)
        ;;
    *)
        printf '\033[31m%s\033[0m %s %s %s\n' "Error:" "invalid action" "'$ACTION'" "(must be up|down|restart)" >&2
        echo
        print_help
        exit 1
        ;;
esac

# Function to run compose in a directory
run_compose_in_dir() {
    dir="${1%/}"

    if [ ! -d "$dir" ]; then
        printf '\033[31m%s\033[0m %s %s %s\n' "Error:" "directory" "'$dir'" "does not exist... skipping." >&2
        return 1
    fi

    set --

    # 1. Core names
    for f in "docker-compose.yml" "docker-compose.yaml" "compose.yml" "compose.yaml"; do
        if [ -f "$dir/$f" ]; then
            set -- "$@" -f "$dir/$f"
        fi
    done

    # 2. Pattern-based
    for f in "$dir"/docker-compose-*.yml "$dir"/docker-compose-*.yaml \
             "$dir"/compose-*.yml        "$dir"/compose-*.yaml; do
        if [ -f "$f" ]; then
            set -- "$@" -f "$f"
        fi
    done

    # If no files were added, $# (arg count) will be 0
    if [ "$#" -eq 0 ]; then
        return 0
    fi

    # Mark that found at least one valid project
    found_any=1

    folder_name=$(basename "$dir")

    printf '\033[35m%s\033[0m\n' "------------------------------------------------"
    printf '\033[1m\033[34m%s\033[0m %s \033[32m%s\033[0m %s \033[36m%s\033[0m\n' \
        "Running:" "docker compose" "$ACTION" "for" "$folder_name"
    printf '\033[1m\033[36m%s\033[0m\n' "Using files:"

    # Display files using a subshell
    (
        while [ "$#" -gt 0 ]; do
            shift               # drop "-f"
            [ "$#" -eq 0 ] && break
            printf '  \033[32m-\033[0m %s\n' "$1"
            shift
        done
    )

    case "$ACTION" in
        up)
            docker compose "$@" up -d
            ;;
        down)
            docker compose "$@" down
            ;;
        restart)
            docker compose "$@" down
            docker compose "$@" up -d
            ;;
    esac
}

# Global tracker for interactive mode
found_any=0

# Non-interactive: explicit directories passed as arguments
if [ "$#" -gt 0 ]; then
    for name in "$@"; do
        run_compose_in_dir "$name"
    done
    exit 0
fi

# Interactive mode
printf '\033[1m\033[36m%s\033[0m\n' "Interactive mode"
printf "Base directory to scan for compose projects [%s]: " "$(pwd)"

if ! IFS= read -r BASE_DIR; then
    exit 1
fi

# Default to current directory if input is empty
if [ -z "$BASE_DIR" ]; then
    BASE_DIR=$(pwd)
fi

if [ ! -d "$BASE_DIR" ]; then
    printf '\033[31m%s\033[0m %s %s %s\n' "Error:" "'$BASE_DIR'" "is not a directory." "" >&2
    exit 1
fi

printf "Folders to exclude (space-separated names under %s, or empty): " "$BASE_DIR"
if ! IFS= read -r EXCLUDES_INPUT; then
    exit 1
fi

is_excluded() {
    check_name="$1"
    for ex in $EXCLUDES_INPUT; do
        if [ "$check_name" = "$ex" ]; then
            return 0
        fi
    done
    return 1
}

# Iterate over subdirectories
for dir in "$BASE_DIR"/*/; do
    [ -d "$dir" ] || continue

    dir=${dir%/}
    folder_name=$(basename "$dir")

    if is_excluded "$folder_name"; then
        printf '\033[33m%s\033[0m %s \033[36m%s\033[0m\n' "Skipping excluded folder:" "" "$folder_name"
        continue
    fi

    # Allow failure so one broken project doesn't stop the sweep
    run_compose_in_dir "$dir" || true
done

if [ "$found_any" -eq 0 ]; then
    printf '\033[33m%s\033[0m %s \033[36m%s\033[0m\n' "No subdirectories with compose files found under" "" "$BASE_DIR"
fi
