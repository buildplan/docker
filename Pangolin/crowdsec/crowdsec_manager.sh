#!/bin/bash

# Define the list of script names
scripts=("master.sh" "utils.sh" "decisions.sh" "enrollment.sh" "whitelist.sh" "scenarios.sh" "captcha.sh" "health_checks.sh" "ip_management.sh")

# Define the base URL for the Gist raw files
base_url="https://raw.githubusercontent.com/hhftechnology/crowdsec_manager/refs/heads/main"

# Download each script
for script in "${scripts[@]}"; do
  curl -o "$script" "$base_url/$script"
done

# Make all .sh files executable
chmod +x *.sh

# Run the master script
./master.sh
