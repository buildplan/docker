#!/bin/sh

# # Compose Manager
# POSIX-compliant script for managing multiple Docker Compose projects.
#
### Features
#   - Manage multiple compose projects in one command
#   - Dry-run mode for safe testing
#   - Interactive wizard or direct directory targeting
#   - Automatic discovery of compose files
#   - Folder exclusion support
#
### Requirements
#   - Docker with Compose plugin
#   - POSIX-compliant shell (sh, dash, bash, zsh)
#
### Usage
#### Interactive mode
#     - ./compose-manager.sh up
#### Direct directories
#     - ./compose-manager.sh restart dir1 dir2 dir3
#### Dry-run (safe testing)
#     - ./compose-manager.sh --dry-run down /path/to/projects
#### Help
#     - ./compose-manager.sh --help

set -eu

SCRIPT_NAME=$(basename "$0")
DRY_RUN=0
FOUND_ANY=0

# --- Helper Functions ---

print_help() {
    printf '\033[1m\033[36m%s\033[0m\n' "Usage:"
    printf '%s\n' "  ./$SCRIPT_NAME [up|down|restart] [options] [DIR1 DIR2 ...]"
    printf '\n'
    printf '\033[1m\033[36m%s\033[0m\n' "Examples:"
    printf '%s\n' "  ./$SCRIPT_NAME up"
    printf '%s\n' "  ./$SCRIPT_NAME restart --dry-run dir1 dir2"
    printf '%s\n' "  ./$SCRIPT_NAME down --dry-run"
    printf '\n'
    printf '\033[1m\033[36m%s\033[0m\n' "Options:"
    printf '%s\n' "  --dry-run    Show what would happen without running docker."
    printf '%s\n' "  -h, --help   Show this help message."
}

check_deps() {
    if ! command -v docker >/dev/null 2>&1; then
        printf '\033[31m%s\033[0m %s\n' "Error:" "Docker is not installed or not in PATH." >&2
        exit 1
    fi
}

validate_action() {
    case "$1" in
        up|down|restart) return 0 ;;
        *)
            printf '\033[31m%s\033[0m %s\n' "Error:" "Invalid action '$1'" >&2
            return 1
            ;;
    esac
}

run_compose_in_dir() {
    dir="${1%/}"
    action="$2"

    if [ ! -d "$dir" ]; then
        printf '\033[31m%s\033[0m %s %s %s\n' "Error:" "Directory" "'$dir'" "does not exist... skipping." >&2
        return 1
    fi

    # Reset positional parameters to build file list safely
    set --

    # 1. Look for standard names
    for f in "docker-compose.yml" "docker-compose.yaml" "compose.yml" "compose.yaml"; do
        if [ -f "$dir/$f" ]; then
            set -- "$@" -f "$dir/$f"
        fi
    done

    # 2. Look for patterns
    for f in "$dir"/docker-compose-*.yml "$dir"/docker-compose-*.yaml \
             "$dir"/compose-*.yml        "$dir"/compose-*.yaml; do
        if [ -f "$f" ]; then
            set -- "$@" -f "$f"
        fi
    done

    # STOP: If no files found, return silently
    if [ "$#" -eq 0 ]; then
        return 0
    fi

    # Update global state
    FOUND_ANY=1
    folder_name=$(basename "$dir")

    printf '\033[35m%s\033[0m\n' "------------------------------------------------"

    if [ "$DRY_RUN" -eq 1 ]; then
        printf '\033[1m\033[33m%s\033[0m %s \033[32m%s\033[0m %s \033[36m%s\033[0m\n' \
           "[DRY-RUN]" "docker compose" "$action" "for" "$folder_name"
    else
        printf '\033[1m\033[34m%s\033[0m %s \033[32m%s\033[0m %s \033[36m%s\033[0m\n' \
           "Running:" "docker compose" "$action" "for" "$folder_name"
    fi

    # List files found
    printf '\033[1m\033[36m%s\033[0m\n' "Using files:"
    for file_arg in "$@"; do
        if [ "$file_arg" != "-f" ]; then
            printf '  \033[32m-\033[0m %s\n' "$(basename "$file_arg")"
        fi
    done

    # --- DRY RUN DISPLAY ---
    if [ "$DRY_RUN" -eq 1 ]; then
        printf "\n\033[33m%s\033[0m\n" "Would execute:"

        printf '  docker compose'
        for arg in "$@"; do
            printf ' %s' "$arg"
        done

        case "$action" in
            up)      printf ' up -d --remove-orphans\n' ;;
            down)    printf ' down --remove-orphans\n' ;;
            restart)
                printf ' down --remove-orphans\n'
                printf '  docker compose'
                for arg in "$@"; do
                    printf ' %s' "$arg"
                done
                printf ' up -d --remove-orphans\n'
                ;;
        esac
        return 0
    fi

    # --- ACTUAL EXECUTION ---
    case "$action" in
        up)
            docker compose "$@" up -d --remove-orphans
            ;;
        down)
            docker compose "$@" down --remove-orphans
            ;;
        restart)
            docker compose "$@" down --remove-orphans
            docker compose "$@" up -d --remove-orphans
            ;;
    esac
}

# --- Main Execution ---

check_deps

# 1. Flexible Argument Parsing
ACTION=""

# This loop allows flags and actions to be mixed before directories
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        up|down|restart)
            if [ -n "$ACTION" ]; then
                printf '\033[31m%s\033[0m %s\n' "Error:" "Action already specified ($ACTION)" >&2
                exit 1
            fi
            ACTION="$1"
            shift
            ;;
        -*)
            printf '\033[31m%s\033[0m %s\n' "Error:" "Unknown option $1" >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

# 2. Handle Action (Wizard if missing)
if [ -z "$ACTION" ]; then
    printf "Select action (up/down/restart): "
    if ! IFS= read -r ACTION; then exit 1; fi
    if [ -z "$ACTION" ]; then print_help; exit 1; fi
fi

if ! validate_action "$ACTION"; then
    exit 1
fi

# 3. Handle Directories
if [ "$#" -gt 0 ]; then
    # Arguments remaining in "$@" are directories
    for target_dir in "$@"; do
        run_compose_in_dir "$target_dir" "$ACTION" || true
    done
else
    # Interactive Scan Mode
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '\033[1m\033[36m%s\033[0m\n' "Interactive mode (DRY RUN)"
    else
        printf '\033[1m\033[36m%s\033[0m\n' "Interactive mode"
    fi

    printf "Base directory to scan [%s]: " "$(pwd)"
    if ! IFS= read -r BASE_DIR; then exit 1; fi
    [ -z "$BASE_DIR" ] && BASE_DIR=$(pwd)

    if [ ! -d "$BASE_DIR" ]; then
        printf '\033[31m%s\033[0m %s\n' "Error:" "'$BASE_DIR' is not a directory." >&2
        exit 1
    fi

    printf "Folders to exclude (space-separated, or empty): "
    if ! IFS= read -r EXCLUDES_INPUT; then exit 1; fi

    for dir in "$BASE_DIR"/*/; do
        [ -d "$dir" ] || continue
        dir=${dir%/}
        folder_name=$(basename "$dir")

        # Exclusions (word splitting intentional for space-separated input)
        skip=0
        # shellcheck disable=SC2086
        for ex in $EXCLUDES_INPUT; do
            if [ "$folder_name" = "$ex" ]; then skip=1; break; fi
        done

        if [ "$skip" -eq 1 ]; then
             printf '\033[33m%s\033[0m %s\n' "Skipping excluded:" "$folder_name"
             continue
        fi

        run_compose_in_dir "$dir" "$ACTION" || true
    done
fi

# 4. Final Summary
if [ "$FOUND_ANY" -eq 0 ]; then
   printf '\n\033[33m%s\033[0m\n' "No valid compose projects were found/processed."
else
   printf '\n\033[32m%s\033[0m\n' "Done."
fi
