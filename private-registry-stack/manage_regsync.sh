#!/bin/bash

# --- Configuration ---
REGSYNC_FILE="regsync.yml"
SECRETS_DIR="./secrets"
LOG_DIR="./logs"
GOTIFY_TOKEN_FILE="${SECRETS_DIR}/gotify_token"
GOTIFY_URL="https://goti.change.this.com"
PRIVATE_REGISTRY_HOST=$(cat "${SECRETS_DIR}/registry_host" 2>/dev/null || echo "registry.change.this.com")
BACKUP_DIR="${LOG_DIR}/regsync_backups"
YQ_CMD="yq"
DRY_RUN=false
# --- End Configuration ---

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Helper Functions ---
log()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
success(){ echo -e "${GREEN}[SUCCESS]${NC} $*"; }

check_yq() {
  if ! command -v "$YQ_CMD" &>/dev/null; then
    error "'yq' command not found. Install yq v4+: https://github.com/mikefarah/yq/"
    exit 1
  fi
  local yq_version
  yq_version=$("$YQ_CMD" --version 2>&1)
  if [[ ! "$yq_version" =~ v4\.[0-9]+(\.[0-9]+)* ]]; then
    error "yq version 4.x is required. Please upgrade. Found: $yq_version"
    exit 1
  fi
}

send_gotify() {
  local title="$1" message="$2" priority="$3"
  if [[ ! -f "${GOTIFY_TOKEN_FILE}" ]]; then warn "Gotify token file missing"; return 1; fi
  local token; token=$(<"$GOTIFY_TOKEN_FILE")
  [[ -z "$token" ]] && { warn "Gotify token file is empty"; return 1; }
  curl -sf --connect-timeout 5 --max-time 10 -X POST "${GOTIFY_URL}/message?token=${token}" \
    -F "title=${title}" -F "message=${message}" -F "priority=${priority}" &>/dev/null # Hide curl output unless debugging needed
  return $?
}

backup_config() {
  mkdir -p "$BACKUP_DIR"
  local ts backup_file
  ts=$(date +%Y%m%d_%H%M%S)
  backup_file="${BACKUP_DIR}/regsync.yml.bak_${ts}"
  if cp "$REGSYNC_FILE" "$backup_file"; then
    success "Backup created: $backup_file"
    return 0
  else
    error "Failed to create backup"
    return 1
  fi
}

get_input() {
  local prompt="$1" __resultvar=$2 default_value="$3" input
  if [[ -n "$default_value" ]]; then
    read -p "$prompt (default: $default_value): " input
    input="${input:-$default_value}" # More concise default assignment
  else
    read -p "$prompt" input
  fi
  # Use printf for safer variable assignment, especially if input contains special chars
  printf -v "$__resultvar" '%s' "$input"
}

get_input_required() {
  local prompt="$1" __resultvar=$2 default_value="$3" input
  while true; do
    if [[ -n "$default_value" ]]; then
      read -p "$prompt (default: $default_value): " input
      input="${input:-$default_value}" # More concise default assignment
    else
      read -p "$prompt" input
    fi
    if [[ -n "$input" ]]; then
        # Use printf for safer variable assignment
        printf -v "$__resultvar" '%s' "$input"
        break
    fi
    warn "Input cannot be empty."
  done
}

# Helper function to get sync entry count
get_sync_count() {
    local count
    # Provide default 0 if yq fails or sync array is null/missing
    count=$("$YQ_CMD" eval '.sync | length // 0' "$REGSYNC_FILE" 2>/dev/null)
    echo "${count:-0}" # Ensure a number is always returned
}


display_entries() {
  log "Current sync entries:"
  echo "┌───────┬───────────────────────────────────────────────────────┐"
  echo "│ ${BLUE}Index${NC} │ ${BLUE}Source Image${NC}                                               │"
  echo "├───────┼───────────────────────────────────────────────────────┤"

  local count
  count=$(get_sync_count)

  if [[ "$count" -eq 0 ]]; then
      echo "│       │ (No sync entries found)                             │"
  else
      # Use eval '.sync[] | .source' for potentially better handling of complex sources
      "$YQ_CMD" eval '.sync[].source' "$REGSYNC_FILE" | cat -n | awk '{
          idx = $1; $1=""; source=substr($0, 2); # Remove index, get rest of line
          gsub(/^[ \t]+|[ \t]+$/, "", source); # Trim leading/trailing whitespace
          printf "│ %-5d │ %-53s │\n", idx, source
      }'
  fi
  echo "└───────┴───────────────────────────────────────────────────────┘"
}

search_entries() {
    echo "--- Search Sync Entries ---"
    local search_term count matching_lines
    count=$(get_sync_count)

    if [[ "$count" -eq 0 ]]; then
        log "No sync entries exist to search."
        return 0 # Not an error, just nothing to do
    fi

    read -p "Enter search term (searches source image paths, case-insensitive): " search_term

    if [[ -z "$search_term" ]]; then
        warn "Search term cannot be empty."
        return 1
    fi

    log "Searching for entries containing '$search_term'..."

    # Get sources, add line numbers, then grep
    matching_lines=$("$YQ_CMD" eval '.sync[].source' "$REGSYNC_FILE" 2>/dev/null | cat -n | grep -i -E -- "${search_term}")

    if [[ -z "$matching_lines" ]]; then
        log "No entries found matching '$search_term'."
    else
        log "Matching sync entries:"
        echo "┌───────┬───────────────────────────────────────────────────────┐"
        echo "│ ${BLUE}Index${NC} │ ${BLUE}Source Image${NC}                                               │"
        echo "├───────┼───────────────────────────────────────────────────────┤"
        echo "$matching_lines" | awk '{
            idx = $1; $1=""; source=substr($0, 2); # Remove index, get rest of line
            gsub(/^[ \t]+|[ \t]+$/, "", source); # Trim leading/trailing whitespace
            printf "│ %-5s │ %-53s │\n", idx, source # Use %s for index for safety
        }'
        echo "└───────┴───────────────────────────────────────────────────────┘"
    fi
}


add_entry() {
  echo "--- Add New Sync Entry ---"
  local source_image target_image image_name image_tag user_org sync_type guessed_target target_image_input

  PS3="Select source registry type: "
  local options=("Docker Hub (Official Image)" "Docker Hub (User/Org Image)" "GHCR" "LSCR (linuxserver.io)" "Other")
  select opt in "${options[@]}"; do
    case $opt in
      "Docker Hub (Official Image)")
        get_input_required "Enter official image name (e.g., python): " image_name
        get_input_required "Enter tag: " image_tag "latest"
        source_image="docker.io/library/${image_name}:${image_tag}"
        target_image="${PRIVATE_REGISTRY_HOST}/library/${image_name}:${image_tag}"
        break ;;
      "Docker Hub (User/Org Image)")
        get_input_required "Enter user/org (e.g., joxit): " user_org
        get_input_required "Enter image name: " image_name
        get_input_required "Enter tag: " image_tag "latest"
        source_image="docker.io/${user_org}/${image_name}:${image_tag}"
        target_image="${PRIVATE_REGISTRY_HOST}/${user_org}/${image_name}:${image_tag}"
        break ;;
      "GHCR")
        get_input_required "Enter full GHCR path (e.g., regclient/regsync): " image_name
        get_input_required "Enter tag: " image_tag "latest"
        source_image="ghcr.io/${image_name}:${image_tag}"
        target_image="${PRIVATE_REGISTRY_HOST}/ghcr.io/${image_name}:${image_tag}"
        break ;;
      "LSCR (linuxserver.io)")
        get_input_required "Enter image name (e.g., jellyfin): " image_name
        get_input_required "Enter tag: " image_tag "latest"
        source_image="lscr.io/linuxserver/${image_name}:${image_tag}"
        target_image="${PRIVATE_REGISTRY_HOST}/lscr.io/linuxserver/${image_name}:${image_tag}"
        break ;;
      "Other")
        get_input_required "Enter full source image path: " source_image
        # Guess target by replacing first part before / with private host
        guessed_target=$(echo "$source_image" | sed -E "s|^[^/]+|${PRIVATE_REGISTRY_HOST}|")
        get_input "Enter full target image path (leave blank to use guess): " target_image_input "$guessed_target"
        target_image="$target_image_input" # Already handles default via get_input
        break ;;
      *) warn "Invalid option $REPLY";;
    esac
  done

  sync_type="image"
  log "Adding entry: $source_image -> $target_image"

  if $DRY_RUN; then
    log "[Dry Run] Would add entry to $REGSYNC_FILE"
  else
    # Ensure the 'sync' array exists before trying to add to it
    "$YQ_CMD" eval --inplace '.sync //= []' "$REGSYNC_FILE"
    local yq_add_command=".sync += [{\"source\": \"$source_image\", \"target\": \"$target_image\", \"type\": \"$sync_type\"}]"
    if "$YQ_CMD" eval --inplace "$yq_add_command" "$REGSYNC_FILE"; then
        success "Successfully added: $source_image"
        send_gotify "[Regsync Config] Added" "Added source: ${source_image}" 4
    else
        error "Failed to modify $REGSYNC_FILE when adding entry."
        send_gotify "[Regsync Config] ERROR" "Failed to add: ${source_image}" 8
        return 1
    fi
  fi
}

delete_entry() {
  echo "--- Delete Sync Entry ---"
  display_entries

  local count entry_number yq_index source_to_delete confirm
  count=$(get_sync_count)

  if [[ "$count" -eq 0 ]]; then
      log "No sync entries exist to delete."
      return 0 # Not an error, just nothing to do
  fi

  get_input_required "Enter the number of the entry to delete (1-$count): " entry_number

  # Validate if the input is a number AND within the valid range
  if [[ ! "$entry_number" =~ ^[1-9][0-9]*$ ]] || [[ "$entry_number" -gt "$count" ]]; then
    error "Invalid input. Please enter a number between 1 and $count."
    return 1
  fi

  # yq uses 0-based indexing
  yq_index=$(($entry_number - 1))

  # Get the source string for the selected entry for confirmation message
  source_to_delete=$("$YQ_CMD" eval ".sync[$yq_index].source" "$REGSYNC_FILE" 2>/dev/null)

  if [[ -z "$source_to_delete" || "$source_to_delete" == "null" ]]; then
    # This case should be rare now due to range check, but good as a failsafe
    error "Could not retrieve source for entry number: $entry_number. Deletion aborted."
    return 1
  fi

  # *** Add Confirmation Step ***
  echo -e "${YELLOW}You are about to delete entry #$entry_number:${NC}"
  echo "  Source: $source_to_delete"
  read -p "Are you sure? [y/N]: " confirm
  # Default to No if input is empty or anything other than Y or y
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
      log "Deletion cancelled by user."
      return 1
  fi
  # --- End Confirmation Step ---


  log "Attempting to delete entry $entry_number: $source_to_delete"

  if $DRY_RUN; then
    log "[Dry Run] Would delete entry index $yq_index (Source: $source_to_delete)"
  else
    # Use the index directly for deletion
    if "$YQ_CMD" eval --inplace "del(.sync[$yq_index])" "$REGSYNC_FILE"; then
        success "Successfully initiated deletion for entry index: $entry_number (Source: $source_to_delete)"
        send_gotify "[Regsync Config] Deleted" "Deleted entry index: ${entry_number} (Source: ${source_to_delete})" 4
    else
        error "yq command failed to delete entry $entry_number."
        send_gotify "[Regsync Config] ERROR" "Deletion command failed for index ${entry_number}, source: ${source_to_delete}" 8
        return 1
    fi
  fi
}

print_help() {
  echo -e "${BLUE}Usage:${NC} $0 [--dry-run] [--help]"
  echo -e "${BLUE}Options:${NC}"
  echo "  --dry-run    Preview changes without modifying files"
  echo "  --help       Show this help message"
  exit 0
}

# --- Parse Args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      log "Dry run mode enabled."
      shift ;;
    --help)
      print_help
      shift ;;
    *)
      error "Unknown option: $1"
      print_help
      exit 1 ;;
  esac
done


# --- Main ---
check_yq || exit 1 # Exit if yq check fails

# Ensure config file exists, create if not and initialize basic structure
if [[ ! -f "$REGSYNC_FILE" ]]; then
    log "Config file '$REGSYNC_FILE' not found. Creating basic file."
    if ! echo 'sync: []' | "$YQ_CMD" eval - > "$REGSYNC_FILE"; then
         error "Failed to create '$REGSYNC_FILE'. Please check permissions."
         exit 1
    fi
    # Add other top-level keys if needed
    # Example: "$YQ_CMD" eval --inplace '.version = "v1alpha1"' "$REGSYNC_FILE"
fi

log "=== Regsync Configuration Manager ==="
# Add a check if yq can actually read the file after ensuring it exists
if ! "$YQ_CMD" eval '.' "$REGSYNC_FILE" >/dev/null 2>&1; then
    error "Failed to parse '$REGSYNC_FILE'. Please check its syntax."
    exit 1
fi


while true; do
  echo ""
  PS3="$(echo -e "${BLUE}Select action:${NC} ")"
  options=("Add Sync Entry" "Delete Sync Entry" "Search Entries" "Show Current Config" "Backup Config" "Exit")
  select opt in "${options[@]}"; do
    case $opt in
      "Add Sync Entry")
        backup_config && add_entry || warn "Add failed or was cancelled."
        break ;;
      "Delete Sync Entry")
        # Backup happens *before* confirmation inside delete_entry if not dry run
        delete_entry || warn "Delete failed or was cancelled."
        break ;; # If delete is cancelled, backup might have happened unnecessarily - minor issue.
                # Alternative: Move backup_config inside delete_entry after confirmation?
      "Search Entries")
        search_entries
        break ;;
      "Show Current Config")
        echo -e "${BLUE}--- $REGSYNC_FILE ---${NC}"
        # Use -C for color output if supported
        "$YQ_CMD" eval -C '.' "$REGSYNC_FILE" 2>/dev/null || "$YQ_CMD" eval '.' "$REGSYNC_FILE"
        echo -e "${BLUE}---------------------${NC}"
        break ;;
      "Backup Config")
        backup_config
        break ;;
      "Exit")
        log "Goodbye!"
        exit 0 ;;
      *) warn "Invalid option $REPLY";;
    esac
  done
done
