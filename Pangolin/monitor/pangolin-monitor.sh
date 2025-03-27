#!/bin/bash

# Replace with your repository's raw URL for the main script
MAIN_SCRIPT_URL="https://raw.githubusercontent.com/hhftechnology/pangolin-monitoring/refs/heads/main/main.sh"

# Replace with your repository's raw URL for the dependent script
DEPENDENT_SCRIPT_URL="https://raw.githubusercontent.com/hhftechnology/pangolin-monitoring/refs/heads/main/discord.sh"

# Replace with the desired filenames (optional, you can keep them the same as in the repo)
MAIN_SCRIPT_FILENAME="main.sh"
DEPENDENT_SCRIPT_FILENAME="discord.sh"

# Download the main script
echo "Downloading main script..."
curl -sSL "$MAIN_SCRIPT_URL" -o "$MAIN_SCRIPT_FILENAME"
if [ $? -ne 0 ]; then
  echo "Error downloading main script."
  exit 1
fi

# Download the dependent script
echo "Downloading dependent script..."
curl -sSL "$DEPENDENT_SCRIPT_URL" -o "$DEPENDENT_SCRIPT_FILENAME"
if [ $? -ne 0 ]; then
  echo "Error downloading dependent script."
  exit 1
fi

# Make the scripts executable
echo "Making scripts executable..."
chmod +x "$MAIN_SCRIPT_FILENAME"
chmod +x "$DEPENDENT_SCRIPT_FILENAME"

# Run the main script
echo "Running main script..."
./"$MAIN_SCRIPT_FILENAME"

# Optional: Cleanup downloaded scripts after execution
# echo "Cleaning up downloaded scripts..."
# rm "$MAIN_SCRIPT_FILENAME" "$DEPENDENT_SCRIPT_FILENAME"
echo "Script execution complete."
exit 0
