#!/bin/bash

# Global variables
log_file="./config/traefik/logs/access.log"           # Default log file
max_lines=5000                    # Default number of lines to analyze
parsed_file=""                    # Temporary file for parsed logs
save_report=false                 # Report saving flag
report_dir=""                     # Directory for CSV reports
ignore_ips=""                     # Comma-separated IPs to ignore
verbose=false                     # Verbose mode flag
threat_threshold=100              # Default threshold for security analysis

# Function to detect log format (simplified)
detect_format() {
    if head -n 1 "$log_file" | grep -q "{"; then
        echo "json"
    else
        echo "common"
    fi
}

# Function to parse logs (simplified for example)
parse_logs() {
    local temp_file=$(mktemp)
    local format=$(detect_format)
    
    if [[ "$format" == "json" ]]; then
        jq -r '[.ClientHost, .RequestMethod, .RequestPath, .DownstreamStatus, (.["request_User-Agent"] // ""), .["request_X-Forwarded-Proto"], .TLSVersion] | join("\t")' "$log_file" | head -n "$max_lines" > "$temp_file"
    else
        awk '{print $1 "\t" $6 "\t" $7 "\t" $9 "\t" $14 "\t" "http" "\t" ""}' "$log_file" | head -n "$max_lines" > "$temp_file"
    fi
    echo "$temp_file"
}

# Filter out ignored IPs
filter_ips() {
    local input_file=$1
    local output_file=$(mktemp)
    if [[ -n "$ignore_ips" ]]; then
        awk -F'\t' -v ips="$ignore_ips" '
        BEGIN { split(ips, arr, ","); for (i in arr) ignore[arr[i]] }
        !($1 in ignore) { print }
        ' "$input_file" > "$output_file"
    else
        cp "$input_file" "$output_file"
    fi
    echo "$output_file"
}

# Analysis Functions
analyze_status_codes() {
    local input_file=$1
    local filtered_file=$(filter_ips "$input_file")
    echo "HTTP Status Code Distribution:"
    awk -F'\t' '{print $4}' "$filtered_file" | sort | uniq -c | sort -nr | while read -r count status; do
        echo "  $status: $count requests"
    done
    if $save_report; then
        echo "status,count" > "$report_dir/status_codes.csv"
        awk -F'\t' '{print $4}' "$filtered_file" | sort | uniq -c | sort -nr | while read -r count status; do
            echo "$status,$count" >> "$report_dir/status_codes.csv"
        done
    fi
    rm "$filtered_file"
}

analyze_top_ips() {
    local input_file=$1
    local filtered_file=$(filter_ips "$input_file")
    echo "Top Client IPs:"
    awk -F'\t' '{print $1}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count ip; do
        echo "  $ip: $count requests"
    done
    if $save_report; then
        echo "ip,count" > "$report_dir/top_ips.csv"
        awk -F'\t' '{print $1}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count ip; do
            echo "$ip,$count" >> "$report_dir/top_ips.csv"
        done
    fi
    rm "$filtered_file"
}

analyze_methods() {
    local input_file=$1
    local filtered_file=$(filter_ips "$input_file")
    echo "HTTP Methods Usage:"
    awk -F'\t' '{print $2}' "$filtered_file" | sort | uniq -c | sort -nr | while read -r count method; do
        echo "  $method: $count requests"
    done
    if $save_report; then
        echo "method,count" > "$report_dir/methods.csv"
        awk -F'\t' '{print $2}' "$filtered_file" | sort | uniq -c | sort -nr | while read -r count method; do
            echo "$method,$count" >> "$report_dir/methods.csv"
        done
    fi
    rm "$filtered_file"
}

analyze_paths() {
    local input_file=$1
    local filtered_file=$(filter_ips "$input_file")
    echo "Top Requested Paths:"
    awk -F'\t' '{print $3}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count path; do
        echo "  $path: $count requests"
    done
    if $save_report; then
        echo "path,count" > "$report_dir/paths.csv"
        awk -F'\t' '{print $3}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count path; do
            echo "$path,$count" >> "$report_dir/paths.csv"
        done
    fi
    rm "$filtered_file"
}

analyze_errors() {
    local input_file=$1
    local filtered_file=$(filter_ips "$input_file")
    echo "Error Analysis (Status >= 400):"
    awk -F'\t' '$4 >= 400 {print $4 "\t" $1 "\t" $3}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count status ip path; do
        echo "  $status from $ip on $path: $count times"
    done
    if $save_report; then
        echo "status,ip,path,count" > "$report_dir/errors.csv"
        awk -F'\t' '$4 >= 400 {print $4 "\t" $1 "\t" $3}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count status ip path; do
            echo "$status,$ip,$path,$count" >> "$report_dir/errors.csv"
        done
    fi
    rm "$filtered_file"
}

analyze_tls() {
    local input_file=$1
    local filtered_file=$(filter_ips "$input_file")
    echo "TLS/SSL Usage:"
    awk -F'\t' '$7 != "" {print $7}' "$filtered_file" | sort | uniq -c | sort -nr | while read -r count tls; do
        echo "  $tls: $count requests"
    done
    if $save_report; then
        echo "tls_version,count" > "$report_dir/tls.csv"
        awk -F'\t' '$7 != "" {print $7}' "$filtered_file" | sort | uniq -c | sort -nr | while read -r count tls; do
            echo "$tls,$count" >> "$report_dir/tls.csv"
        done
    fi
    rm "$filtered_file"
}

analyze_user_agents() {
    local input_file=$1
    local filtered_file=$(filter_ips "$input_file")
    echo "Top User Agents:"
    awk -F'\t' '{print $5}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count ua; do
        echo "  $ua: $count requests"
    done
    if $save_report; then
        echo "user_agent,count" > "$report_dir/user_agents.csv"
        awk -F'\t' '{print $5}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count ua; do
            echo "$ua,$count" >> "$report_dir/user_agents.csv"
        done
    fi
    rm "$filtered_file"
}

analyze_security() {
    local input_file=$1
    local filtered_file=$(filter_ips "$input_file")
    echo "Security Analysis - Suspicious Paths:"
    awk -F'\t' '$3 ~ /\.(git|env|sql|bak)$|wp-|admin|login|phpMyAdmin|actuator|shell|passwd|eval|xmlrpc/ {print $1 "\t" $3}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count ip path; do
        echo "  $ip requested $path: $count times"
    done
    if $save_report; then
        echo "ip,path,count" > "$report_dir/suspicious_paths.csv"
        awk -F'\t' '$3 ~ /\.(git|env|sql|bak)$|wp-|admin|login|phpMyAdmin|actuator|shell|passwd|eval|xmlrpc/ {print $1 "\t" $3}' "$filtered_file" | sort | uniq -c | sort -nr | head -10 | while read -r count ip path; do
            echo "$ip,$path,$count" >> "$report_dir/suspicious_paths.csv"
        done
    fi
    rm "$filtered_file"
}

# Settings menu
settings() {
    while true; do
        echo -e "\nSettings:"
        echo "1. Change log file path (current: $log_file)"
        echo "2. Change number of lines (current: $max_lines)"
        echo "3. Set IPs to ignore (current: $ignore_ips)"
        echo "4. Toggle report saving (current: $save_report)"
        echo "5. Toggle verbose mode (current: $verbose)"
        echo "0. Back"
        read -p "Choose an option: " choice
        case $choice in
            1) read -p "Enter new log file path: " log_file
               if [[ ! -f "$log_file" ]]; then
                   echo "File not found, reverting to previous."
                   continue
               fi
               parsed_file=$(parse_logs)
               ;;
            2) read -p "Enter new number of lines: " max_lines
               parsed_file=$(parse_logs)
               ;;
            3) read -p "Enter IPs to ignore (comma-separated): " ignore_ips ;;
            4) save_report=!$save_report
               if $save_report && [[ -z "$report_dir" ]]; then
                   report_dir="./traefik_analysis_$(date +%Y%m%d_%H%M%S)"
                   mkdir -p "$report_dir"
               fi
               echo "Report saving: $save_report"
               ;;
            5) verbose=!$verbose
               echo "Verbose mode: $verbose"
               ;;
            0) break ;;
            *) echo "Invalid option" ;;
        esac
    done
}

# Main function
main() {
    echo "Welcome to Traefik Log Analyzer"
    read -p "Enter log file path [default: ./config/traefik/logs/access.log]: " input_log
    log_file=${input_log:-./config/traefik/logs/access.log}
    if [[ ! -f "$log_file" ]]; then
        echo "Log file not found."
        exit 1
    fi
    read -p "Enter number of lines to analyze [default: 5000]: " input_lines
    max_lines=${input_lines:-5000}

    parsed_file=$(parse_logs)

    while true; do
        echo -e "\nMenu:"
        echo "1. Analyze HTTP Status Codes"
        echo "2. Analyze Top Client IPs"
        echo "3. Analyze HTTP Methods"
        echo "4. Analyze Top Requested Paths"
        echo "5. Analyze Errors"
        echo "6. Analyze TLS/SSL Usage"
        echo "7. Analyze User Agents"
        echo "8. Analyze Security"
        echo "9. Settings"
        echo "0. Exit"
        read -p "Choose an option: " choice
        case $choice in
            1) analyze_status_codes "$parsed_file" ;;
            2) analyze_top_ips "$parsed_file" ;;
            3) analyze_methods "$parsed_file" ;;
            4) analyze_paths "$parsed_file" ;;
            5) analyze_errors "$parsed_file" ;;
            6) analyze_tls "$parsed_file" ;;
            7) analyze_user_agents "$parsed_file" ;;
            8) analyze_security "$parsed_file" ;;
            9) settings ;;
            0) break ;;
            *) echo "Invalid option" ;;
        esac
        read -p "Press enter to continue..."
    done

    rm -f "$parsed_file"
    if $save_report && [[ -d "$report_dir" ]]; then
        echo "Reports saved in $report_dir"
    fi
}

# Run the script
main
