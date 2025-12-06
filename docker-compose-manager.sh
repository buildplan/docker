#!/bin/sh
# shellcheck shell=dash
#
# docker-compose-manager.sh - Manage Docker Compose projects across directories
# POSIX-compliant utility for up/down/restart/status operations
#

set -eu
( set -o pipefail ) 2>/dev/null && set -o pipefail 2>/dev/null || :

SCRIPT_NAME=$(basename "$0")
VERSION="0.3.0"

# --- Terminal color support detection ---
if [ -t 1 ]; then
    RED='\033[31m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    BLUE='\033[34m'
    MAGENTA='\033[35m'
    CYAN='\033[36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' BOLD='' RESET=''
fi

# --- Global state ---
found_any=0
exit_code=0
DRY_RUN=0
FAILED_DIRS=""
SUCCESS_DIRS=""

# --- Signal handling for clean exit ---
# shellcheck disable=SC2329
cleanup() {
    printf '\n%bInterrupted. Exiting.%b\n' "${YELLOW}" "${RESET}"
    exit 130
}
trap cleanup INT TERM

# --- Dependency check ---
check_dependency() {
    if ! command -v docker >/dev/null 2>&1; then
        printf '%bError:%b %s\n' "${RED}" "${RESET}" "docker is not installed or not in PATH." >&2
        exit 1
    fi

    if ! docker compose version >/dev/null 2>&1; then
        printf '%bError:%b %s\n' "${RED}" "${RESET}" \
            "'docker compose' not available. Install Docker Compose v2 (plugin) or enable the compose plugin." >&2
        exit 1
    fi
}

# --- Help and version ---
print_help() {
    printf '%b%bUsage:%b\n' "${BOLD}" "${CYAN}" "${RESET}"
    printf '  ./%s [OPTIONS] [ACTION] [DIR1 DIR2 ...]\n' "$SCRIPT_NAME"
    printf '  ./%s -h | --help\n' "$SCRIPT_NAME"
    printf '  ./%s -v | --version\n\n' "$SCRIPT_NAME"

    printf '%b%bDescription:%b\n' "${BOLD}" "${CYAN}" "${RESET}"
    cat <<'EOF'
  Run 'docker compose' (up/down/restart/status) in one or more directories.
  Detects standard compose files (compose.yml, docker-compose.yml)
  and pattern-based files (compose-*.yml, docker-compose-*.yml) and merges them.
EOF

    printf '\n%b%bOptions:%b\n' "${BOLD}" "${CYAN}" "${RESET}"
    cat <<EOF
  -h, --help        Show this help message and exit.
  -v, --version     Show version and exit.
  -n, --dry-run     Show what would be done without executing.
EOF

    printf '\n%b%bActions:%b\n' "${BOLD}" "${CYAN}" "${RESET}"
    cat <<EOF
  up                Start containers in detached mode.
  down              Stop and remove containers.
  restart           Restart containers (down + up).
  status            Show container status (docker compose ps).
EOF

    printf '\n%b%bExamples:%b\n' "${BOLD}" "${CYAN}" "${RESET}"
    cat <<EOF
  ./$SCRIPT_NAME up
  ./$SCRIPT_NAME down dir1 dir2
  ./$SCRIPT_NAME --dry-run restart
  ./$SCRIPT_NAME status ./my-app
EOF
}

print_version() {
    printf '%s %s\n' "$SCRIPT_NAME" "$VERSION"
}

# --- Exclusion check ---
is_excluded() {
    case " $EXCLUDES_INPUT " in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

# --- Core: run compose in a directory ---
run_compose_in_dir() {
    dir="${1%/}"
    folder_name=$(basename "$dir")
    cmd_success=0

    if [ ! -d "$dir" ]; then
        printf '%b------------------------------------------------%b\n' "${MAGENTA}" "${RESET}"
        printf '%bError:%b directory %b%s%b does not exist... skipping.\n' \
            "${RED}" "${RESET}" "${CYAN}" "'$dir'" "${RESET}" >&2
        return 1
    fi

    set --

    # 1. Standard priority files
    for f in "compose.yml" "compose.yaml" "docker-compose.yml" "docker-compose.yaml"; do
        if [ -f "$dir/$f" ]; then set -- "$@" -f "$dir/$f"; fi
    done

    # 2. Pattern-based compose files
    for f in "$dir"/docker-compose-*.yml "$dir"/docker-compose-*.yaml \
             "$dir"/compose-*.yml        "$dir"/compose-*.yaml; do
        if [ -f "$f" ]; then set -- "$@" -f "$f"; fi
    done

    if [ "$#" -eq 0 ]; then
        return 0
    fi

    found_any=1

    printf '%b------------------------------------------------%b\n' "${MAGENTA}" "${RESET}"
    printf '%b%bRunning:%b docker compose %b%s%b for %b%s%b\n' \
        "${BOLD}" "${BLUE}" "${RESET}" \
        "${GREEN}" "$ACTION" "${RESET}" \
        "${CYAN}" "$folder_name" "${RESET}"

    # Verbose file listing
    if [ "$DRY_RUN" -eq 0 ]; then
        printf '%b%bUsing files:%b ' "${BOLD}" "${CYAN}" "${RESET}"
        for arg in "$@"; do
            if [ "$arg" != "-f" ]; then printf '%s ' "$(basename "$arg")"; fi
        done
        printf '\n'
    fi

    # Dry-run check
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '%b[dry-run]%b ' "${YELLOW}" "${RESET}"
        case "$ACTION" in
            up)      printf '%s\n' "docker compose $* up -d --remove-orphans" ;;
            down)    printf '%s\n' "docker compose $* down --remove-orphans" ;;
            restart) printf '%s\n' "docker compose $* down --remove-orphans && docker compose $* up -d --remove-orphans" ;;
            status)  printf '%s\n' "docker compose $* ps" ;;
        esac
        return 0
    fi

    # Execute
    case "$ACTION" in
        up)
            if docker compose "$@" up -d --remove-orphans; then cmd_success=1; fi ;;
        down)
            if docker compose "$@" down --remove-orphans; then cmd_success=1; fi ;;

        restart)
            if docker compose "$@" down --remove-orphans; then
                if docker compose "$@" up -d --remove-orphans; then cmd_success=1; fi
            fi ;;
        status)
            if docker compose "$@" ps; then cmd_success=1; fi ;;
    esac

    if [ "$cmd_success" -eq 1 ]; then
        SUCCESS_DIRS="$SUCCESS_DIRS $folder_name"
    else
        printf '%bFailed to execute action for %s%b\n' "${RED}" "$folder_name" "${RESET}"
        FAILED_DIRS="$FAILED_DIRS $folder_name"
        exit_code=1
    fi
}

# --- Argument parsing ---
check_dependency

ACTION=""
EXCLUDES_INPUT=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)    print_help; exit 0 ;;
        -v|--version) print_version; exit 0 ;;
        -n|--dry-run) DRY_RUN=1; shift ;;
        -*)
            printf '%bError:%b unknown option %b%s%b\n' \
                "${RED}" "${RESET}" "${CYAN}" "'$1'" "${RESET}" >&2
            print_help
            exit 1 ;;
        *) break ;;
    esac
done

if [ "$#" -gt 0 ]; then
    ACTION="$1"
    shift
else
    # Interactive selection
    printf 'Select action (up/down/restart/status): '
    if ! IFS= read -r ACTION; then exit 1; fi
    [ -z "$ACTION" ] && { print_help; exit 1; }
fi

case "$ACTION" in
    up|down|restart|status) ;;
    *)
        printf '%bError:%b invalid action %b%s%b (must be up|down|restart|status)\n' \
            "${RED}" "${RESET}" "${CYAN}" "'$ACTION'" "${RESET}" >&2
        print_help
        exit 1
        ;;
esac

# --- Execution ---

# Explicit directories provided
if [ "$#" -gt 0 ]; then
    for name in "$@"; do
        run_compose_in_dir "$name" || true
    done
else
    # Interactive Directory Scan
    printf '%b%bInteractive mode%b\n' "${BOLD}" "${CYAN}" "${RESET}"
    printf 'Base directory to scan [%s]: ' "$(pwd)"

    if ! IFS= read -r BASE_DIR; then exit 1; fi
    if [ -z "$BASE_DIR" ]; then BASE_DIR=$(pwd); fi

    if [ ! -d "$BASE_DIR" ]; then
        printf '%bError:%b %b%s%b is not a directory.\n' \
            "${RED}" "${RESET}" "${CYAN}" "'$BASE_DIR'" "${RESET}" >&2
        exit 1
    fi

    printf 'Folders to exclude (space-separated names): '
    if ! IFS= read -r EXCLUDES_INPUT; then exit 1; fi

    for dir in "$BASE_DIR"/*/; do
        [ -d "$dir" ] || continue

        dir=${dir%/}
        folder_name=$(basename "$dir")

        if is_excluded "$folder_name"; then
            printf '%b------------------------------------------------%b\n' "${MAGENTA}" "${RESET}"
            printf '%bSkipping excluded folder:%b %b%s%b\n' \
                "${YELLOW}" "${RESET}" "${CYAN}" "$folder_name" "${RESET}"
            continue
        fi

        run_compose_in_dir "$dir" || true
    done
fi

if [ "$found_any" -eq 0 ]; then
    printf '\n%bNo subdirectories with compose files found.%b\n' "${YELLOW}" "${RESET}"
else
    printf '\n%b=== Execution Summary ===%b\n' "${BOLD}" "${RESET}"

    if [ -n "$SUCCESS_DIRS" ]; then
        SUCCESS_DIRS=${SUCCESS_DIRS# }
        printf '%bSuccess:%b %s\n' "${GREEN}" "${RESET}" "$SUCCESS_DIRS"
    fi

    if [ -n "$FAILED_DIRS" ]; then
        FAILED_DIRS=${FAILED_DIRS# }
        printf '%bFailed:%b %s\n' "${RED}" "${RESET}" "$FAILED_DIRS"
    fi
fi

exit "$exit_code"
