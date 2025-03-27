#!/usr/bin/env bash
# gotify.sh - Send messages to a Gotify server

# --- Configuration ---
# Priority mapping: Higher number = higher priority
# Discord colors are mapped somewhat arbitrarily here. Adjust as needed.
# Critical/Error (Red) -> Priority 8 (High)
# Warning (Yellow)     -> Priority 6 (Medium-High)
# Info (Blue/Default)  -> Priority 4 (Normal)
# Success (Green)      -> Priority 2 (Low)
DEFAULT_GOTIFY_PRIORITY=4 # Default priority if no color/severity is mapped

# --- Dependencies Check ---
jq --version >/dev/null 2>&1 || { echo "ERROR: jq is not installed. Please install jq." >&2; exit 2; }
curl --version >/dev/null 2>&1 || { echo "ERROR: curl is not installed. Please install curl." >&2; exit 2; }

# --- Help Text ---
help_text="Usage: gotify.sh --gotify-url=<url> --gotify-token=<token> [OPTIONS]

Required:
  --gotify-url <url>       URL of your Gotify server (e.g., https://gotify.example.com)
                           (Can also be set via GOTIFY_URL environment variable)
  --gotify-token <token>   Gotify Application Token
                           (Can also be set via GOTIFY_TOKEN environment variable)

Options (similar to discord.sh where applicable):
  --help                   Display this help and exit
  --title <title>          Set the notification title (Required)
  --description <text>     Set the main message body (Supports Markdown)
  --text <text>            Additional text appended to the description
  --field <Name;Value>     Add a field (Name: Value) to the message body. Can be used multiple times.
                           Note: Inline formatting is not directly supported, fields listed sequentially.
                           Example: --field \"CPU Usage;90%\"
  --color <number>         Discord color code (decimal). Used to determine Gotify priority.
                           Overrides --severity if both are present.
  --severity <level>       Severity level (critical, error, warning, info, success) used to determine priority.
                           Used by the main script. Less priority than --color.
  --url <url>              Set a URL to open when the notification is clicked.
  --footer <text>          Add footer text to the message body.
  --timestamp              (Ignored by Gotify - uses server timestamp) Add timestamp to footer text instead.
  --dry-run                Print the JSON payload and curl command instead of sending.
  --username <name>        (Ignored by Gotify)
  --avatar <url>           (Ignored by Gotify)
  --author <name>          (Ignored by Gotify)
  --thumbnail <url>        (Ignored by Gotify)
  --image <url>            (Ignored by Gotify)
  --footer-icon <url>      (Ignored by Gotify)
  --tts                    (Ignored by Gotify)
  --file <file>            (Not Implemented)
"

# --- Argument Parsing ---
gotify_server_url="${GOTIFY_URL}" # Use ENV var as default
gotify_app_token="${GOTIFY_TOKEN}" # Use ENV var as default
gotify_title=""
message_description=""
message_text=""
message_fields=() # Array to hold fields
gotify_priority=$DEFAULT_GOTIFY_PRIORITY
click_url=""
footer_text=""
add_timestamp_to_footer=false
is_dry_run=false
severity_level="" # Added to accept severity directly

while (( "$#" )); do
  case "${1}" in
    --help|-h) echo "$help_text"; exit 0;;
    --dry-run) is_dry_run=true; shift;;
    --timestamp) add_timestamp_to_footer=true; shift;;

    --gotify-url=*) gotify_server_url="${1#*=}"; shift;;
    --gotify-url) shift; gotify_server_url="${1}"; shift;;

    --gotify-token=*) gotify_app_token="${1#*=}"; shift;;
    --gotify-token) shift; gotify_app_token="${1}"; shift;;

    --title=*) gotify_title="${1#*=}"; shift;;
    --title) shift; gotify_title="${1}"; shift;;

    --description=*) message_description="${1#*=}"; shift;;
    --description) shift; message_description="${1}"; shift;;

    --text=*) message_text="${1#*=}"; shift;;
    --text) shift; message_text="${1}"; shift;;

    --field=*) message_fields+=("${1#*=}"); shift;;
    --field) shift; message_fields+=("${1}"); shift;;

    --color=*) color_code="${1#*=}"; shift;;
    --color) shift; color_code="${1}"; shift;;

    --severity=*) severity_level="${1#*=}"; shift;; # Accept severity
    --severity) shift; severity_level="${1}"; shift;;

    --url=*) click_url="${1#*=}"; shift;;
    --url) shift; click_url="${1}"; shift;;

    --footer=*) footer_text="${1#*=}"; shift;;
    --footer) shift; footer_text="${1}"; shift;;

    # Ignored arguments
    --username=*|--username|--avatar=*|--avatar|--author=*|--author|--author-url=*|--author-url|--author-icon=*|--author-icon|--thumbnail=*|--thumbnail|--image=*|--image|--image-height=*|--image-height|--image-width=*|--image-width|--footer-icon=*|--footer-icon|--tts|--file=*|--file|--modify|--modify=*)
      echo "INFO: Argument '${1%%=*}' is ignored by gotify.sh." >&2
      if [[ "$1" == *=* ]]; then shift; else shift; shift; fi ;;

    *) echo "ERROR: Unknown argument '${1}'" >&2; echo "$help_text"; exit 1;;
  esac
done

# --- Validation ---
if [[ -z "$gotify_server_url" ]]; then
  echo "ERROR: Gotify server URL not provided via --gotify-url or GOTIFY_URL." >&2
  exit 1
fi
# Remove trailing slash from URL if present
gotify_server_url="${gotify_server_url%/}"

if [[ -z "$gotify_app_token" ]]; then
  echo "ERROR: Gotify application token not provided via --gotify-token or GOTIFY_TOKEN." >&2
  exit 1
fi

if [[ -z "$gotify_title" ]]; then
  echo "ERROR: --title is required." >&2
  exit 1
fi

if [[ -z "$message_description" && -z "$message_text" && ${#message_fields[@]} -eq 0 ]]; then
    echo "ERROR: No message content provided via --description, --text, or --field." >&2
    exit 1
fi


# --- Determine Priority ---
# Map color code or severity to Gotify priority
map_priority() {
  local input_color="${1}"
  local input_severity="${2}"
  local priority=$DEFAULT_GOTIFY_PRIORITY # Default

  # Prioritize color code if provided and numeric
  if [[ -n "$input_color" && "$input_color" =~ ^[0-9]+$ ]]; then
      # Mapping based on common discord.sh usage from the main script
      # Red (Critical/Error)
      if (( input_color == 15158332 || input_color == 16711680 )); then priority=8
      # Yellow (Warning)
      elif (( input_color == 16776960 )); then priority=6
      # Green (Success)
      elif (( input_color == 3066993 )); then priority=2
      # Blue (Info) or other colors -> Default
      elif (( input_color == 5814783 )); then priority=4
      fi
      echo "$priority"
      return
  fi

  # Fallback to severity level if color wasn't useful
  case "$input_severity" in
      critical|error) priority=8 ;;
      warning) priority=6 ;;
      info) priority=4 ;;
      success) priority=2 ;;
      *) priority=$DEFAULT_GOTIFY_PRIORITY ;; # Use default if severity is unknown
  esac
  echo "$priority"
}

gotify_priority=$(map_priority "$color_code" "$severity_level")
echo "INFO: Determined Gotify priority: $gotify_priority" >&2


# --- Build Message Body ---
message_body=""

# Add description first
if [[ -n "$message_description" ]]; then
  message_body+="${message_description}"
fi

# Add text (if provided) after description
if [[ -n "$message_text" ]]; then
  # Add newline if description was also present
  [[ -n "$message_body" ]] && message_body+="\n\n"
  message_body+="${message_text}"
fi

# Add fields (as Markdown list)
if [[ ${#message_fields[@]} -gt 0 ]]; then
   [[ -n "$message_body" ]] && message_body+="\n\n---\n" # Separator
   for field_data in "${message_fields[@]}"; do
       # Safely split by the first semicolon only
       field_name="${field_data%%;*}"
       field_value="${field_data#*;}"
       # Escape Markdown characters in name/value if needed (basic example)
       # field_name=$(echo "$field_name" | sed 's/[*`_]/\\&/g')
       # field_value=$(echo "$field_value" | sed 's/[*`_]/\\&/g')
       message_body+="\n* **${field_name}:** ${field_value}"
   done
fi

# Add footer
if [[ -n "$footer_text" ]]; then
    [[ -n "$message_body" ]] && message_body+="\n\n---\n" # Separator
    footer_content="_${footer_text}_" # Italicize footer
    if [[ "$add_timestamp_to_footer" == true ]]; then
         # Get current timestamp in ISO 8601 format
         current_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
         footer_content+=" | ${current_ts}"
    fi
    message_body+="\n${footer_content}"
fi

# --- Construct JSON Payload ---
# Basic payload with title, message, priority, and Markdown content type
json_payload=$(jq -n \
  --arg title "$gotify_title" \
  --arg message "$message_body" \
  --argjson priority "$gotify_priority" \
  '{title: $title, message: $message, priority: $priority, extras: {"client::display": {contentType: "text/markdown"}}}')

# Add click URL if provided
if [[ -n "$click_url" ]]; then
  json_payload=$(echo "$json_payload" | jq --arg url "$click_url" '.extras["client::notification"] = {click: {url: $url}}')
fi

# Check if JSON construction was successful
if [[ -z "$json_payload" ]]; then
    echo "ERROR: Failed to construct JSON payload." >&2
    exit 1
fi

# --- Send Notification ---
target_url="${gotify_server_url}/message"
curl_cmd=(curl --silent --show-error --fail \
  -H "Content-Type: application/json" \
  -H "X-Gotify-Key: $gotify_app_token" \
  -X POST \
  "$target_url" \
  -d "$json_payload"
)

if [[ "$is_dry_run" == true ]]; then
  echo "--- Dry Run ---"
  echo "URL: $target_url"
  echo "Token: $gotify_app_token"
  echo "JSON Payload:"
  echo "$json_payload" | jq '.' # Pretty print JSON
  echo "Curl Command:"
  # Print command safely, quoting arguments
  printf "%q " "${curl_cmd[@]}"
  echo ""
  echo "--- End Dry Run ---"
  exit 0
fi

# Execute curl command
echo "INFO: Sending notification to Gotify..." >&2
response=$("${curl_cmd[@]}" 2>&1) # Capture stdout and stderr
curl_exit_code=$?

# --- Check Response ---
if [[ $curl_exit_code -eq 0 ]]; then
  echo "INFO: Notification sent successfully to Gotify." >&2
  # Gotify returns the sent message object on success, log its ID
  message_id=$(echo "$response" | jq -r '.id // empty')
  [[ -n "$message_id" ]] && echo "INFO: Gotify Message ID: $message_id" >&2
  exit 0
else
  echo "ERROR: Failed to send notification to Gotify (curl Exit Code: $curl_exit_code)." >&2
  echo "ERROR: Target URL: $target_url" >&2
  # Try to parse error from Gotify response if available
  gotify_error=$(echo "$response" | jq -r '.error // empty')
  gotify_error_desc=$(echo "$response" | jq -r '.errorDescription // empty')
  if [[ -n "$gotify_error" ]]; then
      echo "ERROR: Gotify Response: $gotify_error - $gotify_error_desc" >&2
  else
      # If no JSON error, print raw curl response/error
      echo "ERROR: Curl Response/Error: $response" >&2
  fi
  # Optional: Print payload that failed
  # echo "DEBUG: Failed Payload:" >&2
  # echo "$json_payload" | jq '.' >&2
  exit 1
fi
