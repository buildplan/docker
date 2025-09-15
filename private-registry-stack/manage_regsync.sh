#!/bin/bash

# --- Configuration ---
PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
SECRETS_DIR="${PROJECT_DIR}/secrets"
REGSYNC_FILE="${PROJECT_DIR}/regsync.yml"
LOG_DIR="${PROJECT_DIR}/logs"
NTFY_URL=$(<"${SECRETS_DIR}/ntfy_url")
NTFY_TOKEN=$(<"${SECRETS_DIR}/ntfy_token")
NTFY_TOPIC=$(<"${SECRETS_DIR}/ntfy_topic")
PRIVATE_REGISTRY_HOST=$(<"${SECRETS_DIR}/registry_host")
BACKUP_DIR="${LOG_DIR}/regsync_backups"
YQ_CMD="yq" # Path to yq binary if not in default PATH
DRY_RUN=false # Default value, can be overridden by --dry-run flag

# Table Formatting Configuration
INDEX_CONTENT_WIDTH=${INDEX_CONTENT_WIDTH:-5}
if command -v tput >/dev/null 2>&1; then
  TERM_COLS=$(tput cols 2>/dev/null)
fi
: "${TERM_COLS:=${COLUMNS:-80}}"
TABLE_OVERHEAD=7
SOURCE_CONTENT_WIDTH=$(( TERM_COLS - INDEX_CONTENT_WIDTH - TABLE_OVERHEAD ))
(( SOURCE_CONTENT_WIDTH < 32 )) && SOURCE_CONTENT_WIDTH=32

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# --- Helper Functions ---
log()   { echo -e "${BLUE}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
success(){ echo -e "${GREEN}[SUCCESS]${NC} $*"; }

# ANSI-aware, word-boundary wrapping AWK (complete)
read -r -d '' AWK_TABLE_FORMATTER_SCRIPT << 'EOF'
function strip_ansi(s,   t) { t = s; gsub(/\x1B\[[0-9;]*[[:alpha:]]/,"",t); return t }
function vlen(s) { return length(strip_ansi(s)) }
function pad_and_print(idx, line,   pad) {
    pad = SRC_W - vlen(line); if (pad < 0) pad = 0
    printf "│ %s │ %s%*s │\n", idx, line, pad, ""
}
{
    idx_raw  = $1
    content  = $2
    idx_full = sprintf("%-*s", IDX_W, idx_raw)
    idx_blank= sprintf("%-*s", IDX_W, "")

    if (length(content) == 0) { pad_and_print(idx_full, ""); next }

    # Split on spaces; keep any embedded ANSI in tokens
    n = split(content, words, /[[:space:]]+/)
    line = ""; used = 0; first = 1

    for (i = 1; i <= n; i++) {
        w = words[i]; wl = vlen(w)

        # If a single token exceeds the cell and we're at BOL, hard-wrap it
        if (wl > SRC_W && used == 0) {
            # Safe assumption: long tokens (image refs) have no ANSI
            start = 1
            while (start <= length(w)) {
                chunk = substr(w, start, SRC_W)
                pad_and_print(first ? idx_full : idx_blank, chunk)
                first = 0
                start += SRC_W
            }
            line = ""; used = 0
            continue
        }

        if (used == 0) { line = w; used = wl }
        else if (used + 1 + wl <= SRC_W) { line = line " " w; used += 1 + wl }
        else {
            pad_and_print(first ? idx_full : idx_blank, line)
            first = 0
            line = w; used = wl
        }
    }
    if (used > 0) pad_and_print(first ? idx_full : idx_blank, line)
}
EOF

# Function to build the horizontal line for the table
_build_table_horizontal_line() {
    local char_left="$1" char_separator="$2" char_right="$3"
    local line_index_segment=$(printf "%0.s─" $(seq 1 $((INDEX_CONTENT_WIDTH + 2)) ) )
    local line_source_segment=$(printf "%0.s─" $(seq 1 $((SOURCE_CONTENT_WIDTH + 2)) ) )
    echo "${char_left}${line_index_segment}${char_separator}${line_source_segment}${char_right}"
}

# Function to check if yq v4+ exists
check_yq() {
  if ! command -v "$YQ_CMD" &>/dev/null; then error "'yq' command not found. Install yq v4+: https://github.com/mikefarah/yq/"; exit 1; fi
  local yq_version; yq_version=$("$YQ_CMD" --version 2>&1)
  if [[ $? -ne 0 ]] || [[ ! "$yq_version" =~ yq[[:space:]].*[[:space:]]version[[:space:]]v4\.[0-9]+(\.[0-9]+)* ]]; then
    error "yq version 4.x is required. Please install/upgrade. Found: $yq_version"; error "See: https://github.com/mikefarah/yq/"; exit 1;
  fi
}

# Function to send ntfy message
send_ntfy() {
  local title="$1" message="$2" gotify_priority="$3" ntfy_priority

  case "$gotify_priority" in
    8) ntfy_priority="high" ;;
    *) ntfy_priority="default" ;; # For priority 4 and others
  esac

  [[ -z "$NTFY_URL" ]] && { warn "ntfy URL is empty. Check secrets/ntfy_url"; return 1; }
  [[ -z "$NTFY_TOPIC" ]] && { warn "ntfy topic is empty. Check secrets/ntfy_topic"; return 1; }

  local curl_args=()
  curl_args+=(-sf --connect-timeout 5 --max-time 10)
  curl_args+=(-H "Title: ${title}")
  curl_args+=(-H "Priority: ${ntfy_priority}")
  curl_args+=(-d "${message}")

  if [[ -n "$NTFY_TOKEN" ]]; then
    curl_args+=(-H "Authorization: Bearer ${NTFY_TOKEN}")
  fi

  curl "${curl_args[@]}" "${NTFY_URL}/${NTFY_TOPIC}" &>/dev/null
  return $?
}

# Function to create a backup
backup_config() {
  if $DRY_RUN; then log "[Dry Run] Would create backup of $REGSYNC_FILE"; return 0; fi
  mkdir -p "$BACKUP_DIR"
  local ts backup_file; ts=$(date +%Y%m%d_%H%M%S); backup_file="${BACKUP_DIR}/regsync.yml.bak_${ts}"
  if cp "$REGSYNC_FILE" "$backup_file"; then success "Backup created: $backup_file"; return 0;
  else error "Failed to create backup"; return 1; fi
}

# Function to read input with a prompt and default value
get_input() {
  local prompt="$1" __resultvar=$2 default_value="$3" input
  if [[ -n "$default_value" ]]; then read -p "$prompt [Default: $default_value]: " input; input="${input:-$default_value}";
  else read -p "$prompt" input; fi
  printf -v "$__resultvar" '%s' "$input"
}

# Function to read required input with a prompt
get_input_required() {
  local prompt="$1" __resultvar=$2 default_value="$3" input
  while true; do
    if [[ -n "$default_value" ]]; then read -p "$prompt [Default: $default_value]: " input; input="${input:-$default_value}";
    else read -p "$prompt" input; fi
    if [[ -n "$input" ]]; then printf -v "$__resultvar" '%s' "$input"; break; fi
    warn "Input cannot be empty."
  done
}

# Helper function to get sync entry count safely
get_sync_count() {
    local count; count=$("$YQ_CMD" eval '.sync | length // 0' "$REGSYNC_FILE" 2>/dev/null); echo "${count:-0}"
}

# Function to display current sync entries nicely, including type and tags
display_entries() {
    log "Current sync entries:"
    local header_top=$(_build_table_horizontal_line "┌" "┬" "┐")
    local header_middle=$(_build_table_horizontal_line "├" "┼" "┤")
    local header_bottom=$(_build_table_horizontal_line "└" "┴" "┘")
    local title_index_content=$(printf "%-${INDEX_CONTENT_WIDTH}s" "Index")
    local title_source_content=$(printf "%-${SOURCE_CONTENT_WIDTH}s" "Details")

    echo "$header_top"
    echo -e "│ ${BLUE}${title_index_content}${NC} │ ${BLUE}${title_source_content}${NC} │"

    local count; count=$(get_sync_count)
    if [[ "$count" -eq 0 ]]; then
        echo "$header_middle"
        local empty_index_content=$(printf "%-${INDEX_CONTENT_WIDTH}s" " ")
        local no_entries_msg="(No sync entries found)"
        local empty_source_content=$(printf "%-${SOURCE_CONTENT_WIDTH}.*s" "${SOURCE_CONTENT_WIDTH}" "$no_entries_msg")
        echo "│ ${empty_index_content} │ ${empty_source_content} │"
    else
        for (( i=0; i < count; i++ )); do
            echo "$header_middle"

            local entry_lines_builder=()
            local entry_display_index=$((i + 1))

            local source_val; source_val=$("$YQ_CMD" eval ".sync[$i].source // \"\"" "$REGSYNC_FILE")
            local type_val; type_val=$("$YQ_CMD" eval ".sync[$i].type // \"image\"" "$REGSYNC_FILE")

            entry_lines_builder+=("$(printf "%s\t%s%s%s %s" \
              "${entry_display_index}" "${GREEN}" "source:" "${NC}" "${source_val}")")
            entry_lines_builder+=("$(printf "%s\t  %s%s%s %s" \
              "" "${YELLOW}" "type:" "${NC}" "${type_val}")")

            local tags_array=()
            mapfile -t tags_array < <("$YQ_CMD" eval "(.sync[$i].tags.allow // [])[]" "$REGSYNC_FILE")

            if [[ ${#tags_array[@]} -gt 0 ]]; then
                entry_lines_builder+=("$(printf "%s\t  %s%s%s" "" "${MAGENTA}" "tags:" "${NC}")")
                for tag in "${tags_array[@]}"; do
                    entry_lines_builder+=("$(printf "%s\t    - %s" "" "${tag}")")
                done
            fi

            local entry_lines_string; IFS=$'\n'; entry_lines_string="${entry_lines_builder[*]}"
            echo -e "${entry_lines_string}" | awk -F'\t' -v IDX_W="$INDEX_CONTENT_WIDTH" -v SRC_W="$SOURCE_CONTENT_WIDTH" "$AWK_TABLE_FORMATTER_SCRIPT"
        done
    fi
    echo "$header_bottom"
}

# Function to search entries
search_entries() {
    echo "--- Search Sync Entries ---"
    local search_term count matching_indices=()
    count=$(get_sync_count)
    if [[ "$count" -eq 0 ]]; then log "No sync entries exist to search."; return 0; fi
    read -p "Enter search term (searches source image paths, case-insensitive): " search_term
    if [[ -z "$search_term" ]]; then warn "Search term cannot be empty."; return 1; fi
    log "Searching for entries containing '$search_term'..."

    mapfile -t matching_indices < <("$YQ_CMD" eval '(.sync[] | select(.source | test("(?i)'"${search_term}"'")) | path | .[1])' "$REGSYNC_FILE")

    if [[ ${#matching_indices[@]} -eq 0 ]]; then
        log "No entries found matching '$search_term'."
    else
        log "Displaying matching entries:"
        for index in "${matching_indices[@]}"; do
            display_index=$((index + 1))
            source=$("$YQ_CMD" eval ".sync[${index}].source" "$REGSYNC_FILE")
            echo -e "  ${YELLOW}Match at index ${display_index}:${NC} ${source}"
        done
    fi
}

# Function to add a new sync entry using yq
add_entry() {
    echo "--- Add New Sync Entry ---"
    local source_image target_image image_name image_tag user_org ghcr_path lscr_name sync_type guessed_target target_image_input
    local tags_allow_patterns=()

    PS3="$(echo -e "${BLUE}Select source registry type:${NC} ")"
    local options=("Docker Hub (Official Image)" "Docker Hub (User/Org Image)" "GHCR" "LSCR (linuxserver.io)" "Other")
    select opt in "${options[@]}"; do
        case $opt in
            "Docker Hub (Official Image)")
                get_input_required "Enter official image name (e.g., python): " image_name; source_image="docker.io/library/${image_name}"; target_image="${PRIVATE_REGISTRY_HOST}/library/${image_name}"; break ;;
            "Docker Hub (User/Org Image)")
                get_input_required "Enter user/org (e.g., joxit): " user_org; get_input_required "Enter image name: " image_name; source_image="docker.io/${user_org}/${image_name}"; target_image="${PRIVATE_REGISTRY_HOST}/${user_org}/${image_name}"; break ;;
            "GHCR")
                get_input_required "Enter full GHCR path (e.g., regclient/regsync): " ghcr_path; source_image="ghcr.io/${ghcr_path}"; target_image="${PRIVATE_REGISTRY_HOST}/ghcr.io/${ghcr_path}"; break ;;
            "LSCR (linuxserver.io)")
                get_input_required "Enter image name (e.g., jellyfin): " lscr_name; source_image="lscr.io/linuxserver/${lscr_name}"; target_image="${PRIVATE_REGISTRY_HOST}/lscr.io/linuxserver/${lscr_name}"; break ;;
            "Other")
                get_input_required "Enter full source image path (e.g., quay.io/prometheus/node-exporter): " source_image; guessed_target=$(echo "$source_image" | sed -E "s|^[^/]+|${PRIVATE_REGISTRY_HOST}|"); get_input "Enter full target image path: " target_image_input "$guessed_target"; target_image="$target_image_input"; if [[ -z "$target_image" ]]; then error "Target image cannot be empty."; return 1; fi; break ;;
            *) warn "Invalid option $REPLY";;
        esac
    done

    read -p "Will this sync multiple tags (repository) or a single tag (image)? [R/i]: " sync_type_choice
    if [[ "$sync_type_choice" =~ ^[Rr]$ ]]; then
        sync_type="repository"
        log "Enter tag patterns one by one. Press Enter on an empty line to finish."

        while read -r -p "Enter a tag pattern (or Enter to finish): " pattern && [[ -n "$pattern" ]]; do
            tags_allow_patterns+=("$pattern")
        done

        if [[ ${#tags_allow_patterns[@]} -eq 0 ]]; then
            warn "No tag patterns were added for a repository-type sync."
        fi
    else
        sync_type="image"
        get_input_required "Enter the single tag to sync: " image_tag "latest"
        source_image="${source_image}:${image_tag}"
        target_image="${target_image}:${image_tag}"
    fi

    log "Adding entry: $source_image -> $target_image"
    if $DRY_RUN; then log "[Dry Run] Would add entry to $REGSYNC_FILE"; return 0; fi

    "$YQ_CMD" eval --inplace '.sync = .sync // []' "$REGSYNC_FILE"
    local yq_add_command; yq_add_command=$(printf '.sync += [{"source": "%s", "target": "%s", "type": "%s"}]' "$source_image" "$target_image" "$sync_type")

    if [[ ${#tags_allow_patterns[@]} -gt 0 ]]; then
        local tags_json="["
        local first=true
        for pattern in "${tags_allow_patterns[@]}"; do
            if ! $first; then
                tags_json+=","
            fi
            tags_json+="\"$pattern\""
            first=false
        done
        tags_json+="]"

        yq_add_command=$(printf '%s | .sync[-1].tags.allow = %s' "$yq_add_command" "$tags_json")
    fi

    if "$YQ_CMD" eval --inplace "$yq_add_command" "$REGSYNC_FILE"; then
        success "Successfully added: $source_image"
        send_ntfy "[Regsync Config] Added" "Added source: ${source_image}" 4
    else
        error "Failed to modify $REGSYNC_FILE when adding entry."
        send_ntfy "[Regsync Config] ERROR" "Failed to add: ${source_image}" 8
        return 1
    fi
}

# Function to edit an existing sync entry
edit_entry() {
    echo "--- Edit Sync Entry ---"; display_entries
    local count; count=$(get_sync_count)
    if [[ "$count" -eq 0 ]]; then log "No sync entries exist to edit."; return 0; fi
    local entry_number; get_input_required "Enter the number of the entry to edit (1-$count): " entry_number
    if [[ ! "$entry_number" =~ ^[1-9][0-9]*$ ]] || [[ "$entry_number" -gt "$count" ]]; then
        error "Invalid input. Please enter a number between 1 and $count."; return 1;
    fi
    local yq_index=$(($entry_number - 1))

    # Fetch current values
    local current_source; current_source=$("$YQ_CMD" eval ".sync[${yq_index}].source" "$REGSYNC_FILE")
    local current_target; current_target=$("$YQ_CMD" eval ".sync[${yq_index}].target" "$REGSYNC_FILE")
    local current_type; current_type=$("$YQ_CMD" eval ".sync[${yq_index}].type" "$REGSYNC_FILE")

    log "Editing entry #$entry_number:"
    echo "  Current Source: $current_source"
    echo "  Current Target: $current_target"
    echo "  Current Type:   $current_type"

    local new_source new_target new_type
    get_input "Enter new source (blank to keep current): " new_source "$current_source"
    get_input "Enter new target (blank to keep current): " new_target "$current_target"
    get_input "Enter new type [image/repository] (blank to keep current): " new_type "$current_type"

    local yq_update_cmd yq_update_cmd=$(printf ".sync[%d].source = \"%s\" | .sync[%d].target = \"%s\" | .sync[%d].type = \"%s\"" \
        "$yq_index" "$new_source" "$yq_index" "$new_target" "$yq_index" "$new_type")

    # If type is repository, manage tags
    if [[ "$new_type" == "repository" ]]; then
        echo "Managing tags for repository-type entry..."
        PS3="$(echo -e "${YELLOW}Select tag action:${NC} ")"
        local tag_options=("Keep Existing Tags" "Add a Tag Pattern" "Remove a Tag Pattern" "Replace All Tag Patterns")
        select tag_opt in "${tag_options[@]}"; do
            case $tag_opt in
                "Keep Existing Tags") break ;;
                "Add a Tag Pattern")
                    local new_pattern; get_input_required "Enter new tag pattern to add: " new_pattern
                    yq_update_cmd+=$(printf " | .sync[%d].tags.allow += [\"%s\"]" "$yq_index" "$new_pattern")
                    break ;;
                "Remove a Tag Pattern")
                    local current_tags_str; current_tags_str=$("$YQ_CMD" eval ".sync[$yq_index].tags.allow | .[]" "$REGSYNC_FILE")
                    if [[ -z "$current_tags_str" ]]; then warn "No tags exist to remove."; break; fi
                    echo "Current tags:"
                    mapfile -t current_tags < <(echo "$current_tags_str")
                    PS3="Select tag to remove: "
                    select tag_to_remove in "${current_tags[@]}"; do
                        if [[ -n "$tag_to_remove" ]]; then
                            yq_update_cmd+=$(printf " | .sync[%d].tags.allow |= del(select(. == \"%s\"))" "$yq_index" "$tag_to_remove")
                            yq_update_cmd+=$(printf " | if (.sync[%d].tags.allow | length) == 0 then del(.sync[%d].tags) else . end" "$yq_index" "$yq_index")
                            break
                        else
                            warn "Invalid selection."
                        fi
                    done
                    break ;;
                "Replace All Tag Patterns")
                    local new_patterns=()
                    while true; do
                        local pattern
                        read -p "Enter a tag pattern (or press Enter to finish): " pattern
                        [[ -z "$pattern" ]] && break
                        new_patterns+=("$pattern")
                    done
                    if [[ ${#new_patterns[@]} -gt 0 ]]; then
                        local tags_json; tags_json=$("$YQ_CMD" -n '[]' $(for p in "${new_patterns[@]}"; do echo "+ [\"$p\"]"; done) | "$YQ_CMD" -o=json)
                        yq_update_cmd+=$(printf " | .sync[%d].tags.allow = %s" "$yq_index" "$tags_json")
                    else
                        # If user provides no new patterns, delete the tags key
                        yq_update_cmd+=$(printf " | del(.sync[%d].tags)" "$yq_index")
                    fi
                    break ;;
                *) warn "Invalid option $REPLY";;
            esac
        done
    elif [[ "$new_type" == "image" ]] && "$YQ_CMD" -e ".sync[${yq_index}].tags" "$REGSYNC_FILE" >/dev/null; then
        # If changing type from repository to image, remove the old tags
        yq_update_cmd+=$(printf " | del(.sync[%d].tags)" "$yq_index")
        log "Type changed to 'image', removing obsolete tag patterns."
    fi

    echo -e "${YELLOW}Reviewing changes for entry #$entry_number...${NC}"
    if $DRY_RUN; then
        log "[Dry Run] Would apply the following yq command:"
        echo "  $YQ_CMD eval --inplace '$yq_update_cmd' '$REGSYNC_FILE'"
        return 0
    fi

    local confirm; read -p "Are you sure you want to apply these changes? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then log "Edit cancelled by user."; return 1; fi

    if ! backup_config; then error "Backup failed. Aborting edit."; return 1; fi
    if "$YQ_CMD" eval --inplace "$yq_update_cmd" "$REGSYNC_FILE"; then
        success "Successfully updated entry #$entry_number."
        send_ntfy "[Regsync Config] Edited" "Edited entry #${entry_number}. New source: ${new_source}" 4
    else
        error "yq command failed to update entry #$entry_number."
        send_ntfy "[Regsync Config] ERROR" "Edit command failed for entry #${entry_number}" 8
        return 1
    fi
}

# Function to delete a sync entry using yq by index
delete_entry() {
    echo "--- Delete Sync Entry ---"; display_entries
    local count; count=$(get_sync_count)
    if [[ "$count" -eq 0 ]]; then log "No sync entries exist to delete."; return 0; fi
    local entry_number; get_input_required "Enter the number of the entry to delete (1-$count): " entry_number
    if [[ ! "$entry_number" =~ ^[1-9][0-9]*$ ]] || [[ "$entry_number" -gt "$count" ]]; then
        error "Invalid input. Please enter a number between 1 and $count."; return 1;
    fi

    local yq_index=$(($entry_number - 1))
    local source_to_delete; source_to_delete=$("$YQ_CMD" eval ".sync[$yq_index].source" "$REGSYNC_FILE" 2>/dev/null)
    if [[ -z "$source_to_delete" || "$source_to_delete" == "null" ]]; then
        error "Could not retrieve source for entry #$entry_number. Deletion aborted."; return 1;
    fi

    echo -e "${YELLOW}You are about to delete entry #$entry_number:${NC} (Source: $source_to_delete)"
    local confirm; read -p "Are you sure? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then log "Deletion cancelled by user."; return 1; fi

    if $DRY_RUN; then log "[Dry Run] Would delete entry index $yq_index"; return 0; fi
    if ! backup_config; then error "Backup failed. Aborting delete."; return 1; fi

    if "$YQ_CMD" eval --inplace "del(.sync[$yq_index])" "$REGSYNC_FILE"; then
        success "Successfully deleted entry: $source_to_delete"
        send_ntfy "[Regsync Config] Deleted" "Deleted: ${source_to_delete}" 4
    else
        error "yq command failed to delete entry #$entry_number."
        send_ntfy "[Regsync Config] ERROR" "Deletion command failed for: ${source_to_delete}" 8
        return 1
    fi
}

# Function to print help message
print_help() {
  echo -e "${BLUE}Usage:${NC} $0 [--dry-run] [--help]"
  echo -e "  Interactively manage the regsync.yml configuration file.\n"
  echo -e "${BLUE}Options:${NC}"
  echo "  --dry-run      Preview changes without modifying files."
  echo "  --help         Show this help message."
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; log "[DRY RUN MODE ENABLED]"; shift ;;
    --help) print_help; exit 0 ;;
    *) error "Unknown option: $1"; print_help; exit 1 ;;
  esac
done

# --- Main Execution ---
check_yq || exit 1
if [[ ! -f "$REGSYNC_FILE" ]]; then
    log "Config file '$REGSYNC_FILE' not found. Creating basic file."
    if ! printf 'version: 1\ncreds: []\ndefaults:\n  interval: 12h\n  parallel: 1\nsync: []\n' | "$YQ_CMD" eval - > "$REGSYNC_FILE"; then
        error "Failed to create '$REGSYNC_FILE'."; exit 1;
    fi
fi
if ! "$YQ_CMD" eval '.' "$REGSYNC_FILE" >/dev/null 2>&1; then
    error "Failed to parse '$REGSYNC_FILE'. Check its syntax."; exit 1;
fi

log "=== Regsync Configuration Manager (using yq) ==="
while true; do
  echo ""
  PS3="$(echo -e "${BLUE}Select action:${NC} ")"
  options=("Show Entries" "Add Entry" "Edit Entry" "Delete Entry" "Search Entries" "Backup Config" "Exit")
  select opt in "${options[@]}"; do
    case $opt in
      "Show Entries") display_entries; break ;;
      "Add Entry")
        if ! $DRY_RUN; then backup_config || { warn "Backup failed. Aborting add."; break; }; fi
        add_entry || warn "Add failed or was cancelled."; break ;;
      "Edit Entry")
        edit_entry || warn "Edit failed or was cancelled."; break ;;
      "Delete Entry")
        delete_entry || warn "Delete failed or was cancelled."; break ;;
      "Search Entries") search_entries; break ;;
      "Backup Config") backup_config; break ;;
      "Exit") log "Goodbye!"; exit 0 ;;
      *) warn "Invalid option $REPLY";;
    esac
  done
done
