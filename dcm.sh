#!/bin/sh
# shellcheck shell=sh
#
# docker-compose-manager.sh - Manage Docker Compose projects across directories
# POSIX-compliant utility for up/down/restart/status/pull/logs operations
#

set -eu
# Try to set pipefail if available (bash/zsh), ignore if strictly POSIX sh (dash)
# shellcheck disable=SC3040
(set -o pipefail 2>/dev/null) && set -o pipefail

# Ensure standard sorting and character handling
export LC_ALL=C

SCRIPT_NAME=$(basename "$0")
VERSION="0.5.2"

# --- Terminal color support detection ---
if [ -t 1 ]; then
    RED='\033[31m' GREEN='\033[32m' YELLOW='\033[33m' BLUE='\033[34m'
    MAGENTA='\033[35m' CYAN='\033[36m' BOLD='\033[1m' RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' BOLD='' RESET=''
fi

# --- Global state ---
found_any=0
exit_code=0
DRY_RUN=0
FAILED_DIRS=""
SUCCESS_DIRS=""
SKIP_CONFIRM=0

# --- Signal handling for clean exit ---
# shellcheck disable=SC2329
cleanup() {
    exit_status=$?
    if [ "$exit_status" -eq 130 ]; then
        printf '\n%bInterrupted. Exiting.%b\n' "${YELLOW}" "${RESET}"
    fi
    exit "$exit_status"
}
trap cleanup INT TERM

# --- Dependency check ---
check_dependency() {
    if ! command -v docker >/dev/null 2>&1; then
        printf '%bError:%b docker is not installed or not in PATH.\n' "${RED}" "${RESET}" >&2
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        printf '%bError:%b Docker daemon is not running.\n' "${RED}" "${RESET}" >&2
        exit 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        printf '%bError:%b docker compose not available. Install Docker Compose v2 (plugin).\n' \
            "${RED}" "${RESET}" >&2
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
  Run 'docker compose' (up/down/restart/status/pull/logs) in one or more directories.
  Detects and merges compose files in deterministic order:
    1. Standard files: compose.yml, docker-compose.yml
    2. Pattern files (Sorted Alphabetically):
       - compose-*.yml
       - docker-compose-*.yml
       - *-compose.yml (e.g., myapp-compose.yml)
       - *_compose.yml (e.g., db_compose.yml)
EOF

    printf '\n%b%bOptions:%b\n' "${BOLD}" "${CYAN}" "${RESET}"
    cat <<EOF
  -h, --help        Show this help message and exit.
  -v, --version     Show version and exit.
  -n, --dry-run     Show what would be done without executing.
  -y, --yes         Skip confirmation prompts for destructive operations.
EOF

    printf '\n%b%bActions:%b\n' "${BOLD}" "${CYAN}" "${RESET}"
    cat <<EOF
  up                Start containers in detached mode.
  down              Stop and remove containers.
  restart           Restart containers (down + up) for clean config reload.
  pull              Pull the latest images for the services.
  logs              Follow container logs (Ctrl+C moves to next dir).
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

# --- Load config file if exists ---
load_config() {
    config_file="${1}/.docker-compose-manager.conf"
    if [ -f "$config_file" ]; then
        printf '%bInfo:%b Loading exclusions from config file.\n' "${BLUE}" "${RESET}"
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in
                \#*|'') continue ;;
                *) EXCLUDES_INPUT="${EXCLUDES_INPUT} ${line}" ;;
            esac
        done < "$config_file"
        EXCLUDES_INPUT="${EXCLUDES_INPUT# }"
    fi
}

# --- Core: run compose in a directory ---
run_compose_in_dir() {
    dir="${1%/}"
    folder_name=$(basename "$dir")
    cmd_success=0
    compose_files="|"
    temp_file_list=""

    if [ ! -d "$dir" ]; then
        printf '%b------------------------------------------------%b\n' "${MAGENTA}" "${RESET}"
        printf '%bError:%b directory %b%s%b does not exist... skipping.\n' \
            "${RED}" "${RESET}" "${CYAN}" "$folder_name" "${RESET}" >&2
        return 1
    fi

    # --- Phase 1: Collect standard priority files (in specific order) ---
    for f in "compose.yml" "compose.yaml" "docker-compose.yml" "docker-compose.yaml"; do
        if [ -f "$dir/$f" ]; then
            compose_files="${compose_files}${dir}/${f}|"
        fi
    done

    # --- Phase 2: Collect pattern-based files for sorting ---
    temp_file_list=""
    for pattern in "compose-*.yml" "compose-*.yaml" \
                   "docker-compose-*.yml" "docker-compose-*.yaml" \
                   "*-compose.yml" "*-compose.yaml" \
                   "*_compose.yml" "*_compose.yaml"; do

        for f in "$dir"/$pattern; do
            [ -f "$f" ] || continue
            case "$compose_files" in
                *"|${f}|"*) continue ;;
                *)
                    temp_file_list="${temp_file_list}${f}
"
                    ;;
            esac
        done
    done

    if [ -n "$temp_file_list" ]; then
        while IFS= read -r f; do
            [ -n "$f" ] && compose_files="${compose_files}${f}|"
        done <<EOF
$(printf '%s' "$temp_file_list" | sort)
EOF
    fi

    # No compose files found
    if [ "$compose_files" = "|" ]; then
        return 0
    fi

    found_any=1

    # --- Build argument list from collected files ---
    set --
    IFS='|'
    for f in $compose_files; do
        if [ -n "$f" ]; then
            set -- "$@" -f "$f"
        fi
    done
    unset IFS

    printf '%b------------------------------------------------%b\n' "${MAGENTA}" "${RESET}"
    printf '%b%bRunning:%b docker compose %b%s%b for %b%s%b\n' \
        "${BOLD}" "${BLUE}" "${RESET}" \
        "${GREEN}" "$ACTION" "${RESET}" \
        "${CYAN}" "$folder_name" "${RESET}"

    # Verbose file listing
    if [ "$DRY_RUN" -eq 0 ]; then
        printf '%b%bUsing files:%b ' "${BOLD}" "${CYAN}" "${RESET}"
        for arg in "$@"; do
            if [ "$arg" != "-f" ]; then
                printf '%s ' "$(basename "$arg")"
            fi
        done
        printf '\n'
    fi
    # Dry-run output
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '%b[dry-run]%b docker compose' "${YELLOW}" "${RESET}"
        for arg in "$@"; do printf ' %s' "$arg"; done
        case "$ACTION" in
            up)      printf ' up -d --remove-orphans\n' ;;
            down)    printf ' down --remove-orphans\n' ;;
            restart) printf ' down --remove-orphans && docker compose ... up -d --remove-orphans\n' ;;
            pull)    printf ' pull\n' ;;
            logs)    printf ' logs -f\n' ;;
            status)  printf ' ps\n' ;;
        esac
        return 0
    fi

    # --- Execute action ---
    cmd_success=0
    case "$ACTION" in
        up)
            if docker compose "$@" up -d --remove-orphans; then cmd_success=1; fi ;;
        down)
            if docker compose "$@" down --remove-orphans; then cmd_success=1; fi ;;
        restart)
            if docker compose "$@" down --remove-orphans; then
                if docker compose "$@" up -d --remove-orphans; then
                    cmd_success=1
                fi
            fi
            ;;
        pull)
            if docker compose "$@" pull; then cmd_success=1; fi ;;
        logs)
            docker compose "$@" logs -f || true
            cmd_success=1
            ;;
        status)
            if docker compose "$@" ps; then cmd_success=1; fi ;;
    esac

    if [ "$cmd_success" -eq 1 ]; then
        SUCCESS_DIRS="${SUCCESS_DIRS} ${folder_name}"
    else
        printf '%bFailed to execute %s for %s%b\n' \
            "${RED}" "$ACTION" "$folder_name" "${RESET}" >&2
        FAILED_DIRS="${FAILED_DIRS} ${folder_name}"
        exit_code=1
    fi
}

# --- Confirmation prompt for destructive operations ---
confirm_action() {
    if [ "$SKIP_CONFIRM" -eq 1 ] || [ ! -t 0 ]; then
        return 0
    fi
    case "$ACTION" in
        down|restart)
            printf '%b%bWarning:%b This will %s all discovered Docker Compose projects.\n' \
                "${BOLD}" "${YELLOW}" "${RESET}" "$ACTION"
            printf 'Continue? (y/N): '

            IFS= read -r confirm || return 1
            case "$confirm" in
                y|Y|yes|YES) return 0 ;;
                *)
                    printf 'Operation cancelled.\n'
                    exit 0
                    ;;
            esac
            ;;
    esac
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
        -y|--yes)     SKIP_CONFIRM=1; shift ;;
        -*)
            printf '%bError:%b unknown option %b%s%b\n' \
                "${RED}" "${RESET}" "${CYAN}" "$1" "${RESET}" >&2
            print_help
            exit 1
            ;;
        *)
            if [ -z "$ACTION" ]; then
                ACTION="$1"
            else
                break
            fi
            shift
            ;;
    esac
done

# Interactive action prompt if not provided
if [ -z "$ACTION" ]; then
    printf 'Select action (up/down/restart/pull/logs/status): '
    IFS= read -r ACTION || exit 1
    [ -z "$ACTION" ] && { print_help; exit 1; }
fi

# Validate action
case "$ACTION" in
    up|down|restart|status|pull|logs) ;;
    *)
        printf '%bError:%b invalid action %b%s%b\n' \
            "${RED}" "${RESET}" "${CYAN}" "$ACTION" "${RESET}" >&2
        print_help
        exit 1
        ;;
esac

# --- Execution ---
if [ "$#" -gt 0 ]; then
    # Direct directory arguments provided
    for name in "$@"; do
        run_compose_in_dir "$name" || true
    done
else
    # Interactive Directory Scan Mode
    if [ -t 1 ]; then
        printf '%b%bInteractive mode%b\n' "${BOLD}" "${CYAN}" "${RESET}"
        printf 'Base directory to scan [%s]: ' "$(pwd)"
    fi
    # Read base dir, default to pwd if empty
    IFS= read -r BASE_DIR || BASE_DIR=""
    if [ -z "$BASE_DIR" ]; then
        BASE_DIR="$(pwd)"
    fi
    if [ ! -d "$BASE_DIR" ]; then
        printf '%bError:%b %b%s%b is not a directory.\n' \
            "${RED}" "${RESET}" "${CYAN}" "$BASE_DIR" "${RESET}" >&2
        exit 1
    fi

    # Load config file exclusions if exists
    load_config "$BASE_DIR"

    # Interactive exclusion input
    if [ -t 0 ]; then
        if [ -n "$EXCLUDES_INPUT" ]; then
            printf 'Current exclusions from config: %b%s%b\n' \
                "${CYAN}" "$EXCLUDES_INPUT" "${RESET}"
            printf 'Additional folders to exclude (space-separated, or press Enter): '
        else
            printf 'Folders to exclude (space-separated names, or press Enter): '
        fi
        IFS= read -r extra_excludes || true
        if [ -n "$extra_excludes" ]; then
            EXCLUDES_INPUT="${EXCLUDES_INPUT} ${extra_excludes}"
        fi
    fi

    # Confirmation prompt before executing on multiple directories
    confirm_action

    # Scan and execute
    for dir in "$BASE_DIR"/*/; do
        [ -d "$dir" ] || continue
        dir="${dir%/}"
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

# --- Summary ---
if [ "$found_any" -eq 0 ]; then
    printf '\n%bNo subdirectories with compose files found.%b\n' "${YELLOW}" "${RESET}"
else
    if [ "$ACTION" != "logs" ]; then
        printf '\n%b%b=== Summary ===%b\n' "${BOLD}" "${MAGENTA}" "${RESET}"
        if [ -n "$SUCCESS_DIRS" ]; then
            SUCCESS_DIRS="${SUCCESS_DIRS# }"
            printf '%b  [OK] Success:%b %s\n' "${GREEN}" "${RESET}" "$SUCCESS_DIRS"
        fi
        if [ -n "$FAILED_DIRS" ]; then
            FAILED_DIRS="${FAILED_DIRS# }"
            printf '%b  [!!] Failed:%b  %s\n' "${RED}" "${RESET}" "$FAILED_DIRS"
        fi
        printf '\n'
    fi
fi

exit "$exit_code"