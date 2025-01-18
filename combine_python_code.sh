#!/bin/bash
output_file="combined_python_code.txt"

# Remove the output file if it already exists
rm -f "$output_file"

# Function to process files
process_files() {
  local dir="$1"
  local prefix="$2"
  for item in "$dir"/*; do
    if [ -d "$item" ]; then
      # If it's a directory we're interested in, print the directory name and recurse
      case "$(basename "$item")" in
        __pycache__|.git|static|templates|.pythonlibs|.upm)
          # Skip these directories
          ;;
        *)
          echo "Directory: $prefix$(basename "$item")" >> "$output_file"
          echo "" >> "$output_file"
          process_files "$item" "$prefix  "
          ;;
      esac
    elif [ -f "$item" ]; then
      # If it's a file with a relevant extension, print its content
      case "$item" in
        *.py|*.toml|*.lock|*.nix|*.replit|*.html)
          # Exclude generated files and logs
          if [[ "$item" != *"__pycache__"* && "$item" != *".log"* ]]; then
            echo "File: $prefix$(basename "$item")" >> "$output_file"
            echo "" >> "$output_file"
            cat "$item" >> "$output_file"
            echo "" >> "$output_file"
            echo "----------------------------------------" >> "$output_file"
            echo "" >> "$output_file"
          fi
          ;;
      esac
    fi
  done
}

# Process specific configuration files
process_config_files() {
  local files=("pyproject.toml" "requirements.txt" "README.md" ".replit" "replit.nix")
  for file in "${files[@]}"; do
    if [ -f "$file" ]; then
      echo "File: $file" >> "$output_file"
      echo "" >> "$output_file"
      cat "$file" >> "$output_file"
      echo "" >> "$output_file"
      echo "----------------------------------------" >> "$output_file"
      echo "" >> "$output_file"
    fi
  done
}

# Start processing from the current directory
process_files "." ""

# Process configuration files
process_config_files

echo "Selected files have been combined into $output_file"