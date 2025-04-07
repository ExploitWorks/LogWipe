#!/bin/bash

# Helper utilities for LogWipe

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a file exists and is writable
check_file() {
    if [ ! -f "$1" ]; then
        touch "$1" 2>/dev/null || {
            echo "Error: Cannot create file $1"
            log_action "Error: Cannot create file $1"
            return 1
        }
    fi
    [ -w "$1" ] || {
        echo "Error: Cannot write to file $1"
        log_action "Error: Cannot write to file $1"
        return 1
    }
    return 0
}

# Function to restore a file from backup
restore_file() {
    local file="$1"
    if [ -f "${file}.bak" ]; then
        mv "${file}.bak" "$file" 2>/dev/null || {
            echo "Error: Could not restore $file from backup"
            log_action "Error: Could not restore $file from backup"
            return 1
        }
        log_action "Restored $file from backup"
    fi
    return 0
}

# Function to generate a random string
generate_random_string() {
    local length=${1:-32}
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length"
}

# Function to securely delete files with multiple overwrites
secure_delete() {
    local file="$1"
    local passes="${2:-3}"
    
    show_notification "Securely deleting $file..." "info"
    log_action "Started secure deletion of $file"
    
    # Verify file exists
    if [ ! -f "$file" ]; then
        show_notification "Error: File not found: $file" "error"
        log_action "Error: File not found: $file"
        return 1
    fi
    
    # Check if shred is available
    if command_exists shred; then
        shred -f -z -u -n "$passes" "$file" 2>/dev/null
        local status=$?
    else
        # Fallback if shred is not available
        # Create a temporary file with random data
        for ((i=1; i<=passes; i++)); do
            dd if=/dev/urandom of="$file" bs=8k count=$(($(stat -c %s "$file")/8192 + 1)) conv=notrunc 2>/dev/null
        done
        
        # Final pass with zeros
        dd if=/dev/zero of="$file" bs=8k count=$(($(stat -c %s "$file")/8192 + 1)) conv=notrunc 2>/dev/null
        
        # Remove the file
        rm -f "$file" 2>/dev/null
        local status=$?
    fi
    
    if [ $status -eq 0 ]; then
        show_notification "Successfully deleted $file securely" "success"
        log_action "Completed secure deletion of $file"
    else
        show_notification "Error: Failed to securely delete $file" "error"
        log_action "Error: Failed to securely delete $file"
        return 1
    fi
    
    return 0
}

# Function to securely delete the entire LogWipe tool
self_destruct() {
    show_notification "INITIATING SELF-DESTRUCT SEQUENCE..." "warning"
    log_action "Self-destruct sequence initiated"
    
    # Get confirmation with a clear warning
    if ! confirm_action "WARNING: This will securely erase ALL LogWipe files and traces. This action CANNOT be undone. Continue?" "N"; then
        show_notification "Self-destruct aborted" "info"
        log_action "Self-destruct aborted by user"
        return 1
    fi
    
    # Get second confirmation
    if ! confirm_action "Are you ABSOLUTELY CERTAIN you want to erase LogWipe completely from this system?" "N"; then
        show_notification "Self-destruct aborted" "info"
        log_action "Self-destruct aborted at final confirmation"
        return 1
    fi
    
    # Get third confirmation with a random verification code
    local verification_code=$(tr -dc 'A-Z0-9' < /dev/urandom | head -c 6)
    echo -e "${RED}Final verification required.${NC}"
    echo -e "To confirm deletion, please type this code: ${YELLOW}${verification_code}${NC}"
    read -p "Verification code: " user_code
    
    if [ "$user_code" != "$verification_code" ]; then
        show_notification "Incorrect verification code. Self-destruct aborted." "info"
        log_action "Self-destruct aborted: incorrect verification code"
        return 1
    fi
    
    show_notification "Self-destruct confirmed. Proceeding with secure deletion..." "info"
    
    # Determine the absolute path of the script directory for safety
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.."
    local real_script_dir="$(realpath "$script_dir")"
    
    # Additional safety checks
    if [ -z "$real_script_dir" ] || [ "$real_script_dir" = "/" ] || [ "$real_script_dir" = "/home" ] || [ "$real_script_dir" = "/usr" ] || [ "$real_script_dir" = "/etc" ] || [ "$real_script_dir" = "/bin" ] || [ "$real_script_dir" = "/sbin" ]; then
        show_notification "CRITICAL ERROR: Script directory resolved to a system directory. Self-destruct aborted for safety." "error"
        log_action "Self-destruct aborted: script directory resolved to a system directory: $real_script_dir"
        return 1
    fi
    
    # Check if the script directory contains LogWipe files
    if [ ! -f "$real_script_dir/logwipe.sh" ] || [ ! -d "$real_script_dir/src" ]; then
        show_notification "CRITICAL ERROR: Directory doesn't appear to be a LogWipe installation. Self-destruct aborted for safety." "error"
        log_action "Self-destruct aborted: directory doesn't appear to be a LogWipe installation: $real_script_dir"
        return 1
    fi
    
    # Before proceeding, lock down permissions to ensure we can delete everything
    chmod -R 700 "$real_script_dir" 2>/dev/null
    
    local passes=7  # Increased from 3 to 7 passes for more secure deletion
    
    # Show progress bar while deleting
    echo -e "${YELLOW}Initiating secure deletion process...${NC}"
    
    # Create self-destruct script that will run after this process exits
    # This ensures complete removal even if the main process is terminated
    local self_destruct_script="/tmp/logwipe_erase_$RANDOM.sh"
    
    echo "#!/bin/bash" > "$self_destruct_script"
    echo "# LogWipe self-destruct cleanup script" >> "$self_destruct_script"
    echo "sleep 2 # Give the main process time to exit" >> "$self_destruct_script"
    echo "echo 'Completing LogWipe removal...'" >> "$self_destruct_script"
    
    # Clean shell histories for all users and all shells
    echo "# Removing LogWipe from shell histories" >> "$self_destruct_script"
    echo "if [ \"\$(id -u)\" = \"0\" ]; then" >> "$self_destruct_script"
    echo "  # If running as root, clean all user histories" >> "$self_destruct_script"
    echo "  for user_home in /home/*/ /root/; do" >> "$self_destruct_script"
    echo "    for histfile in \"\${user_home}.bash_history\" \"\${user_home}.zsh_history\" \"\${user_home}.history\" \"\${user_home}.sh_history\" \"\${user_home}.ksh_history\" \"\${user_home}.fish_history\"; do" >> "$self_destruct_script"
    echo "      if [ -f \"\$histfile\" ]; then" >> "$self_destruct_script"
    echo "        sed -i '/logwipe/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "        sed -i '/LogWipe/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "        sed -i '/self-destruct/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "        sed -i '/self_destruct/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "        sed -i '/anti-forensic/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "        sed -i '/anti_forensic/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "        sed -i '/kernel_cleaner/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "        sed -i '/hardware_cleaner/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "      fi" >> "$self_destruct_script"
    echo "    done" >> "$self_destruct_script"
    echo "  done" >> "$self_destruct_script"
    echo "else" >> "$self_destruct_script"
    echo "  # Clean current user's history" >> "$self_destruct_script"
    echo "  for histfile in ~/.bash_history ~/.zsh_history ~/.history ~/.sh_history ~/.ksh_history ~/.fish_history; do" >> "$self_destruct_script"
    echo "    if [ -f \"\$histfile\" ]; then" >> "$self_destruct_script"
    echo "      sed -i '/logwipe/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "      sed -i '/LogWipe/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "      sed -i '/self-destruct/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "      sed -i '/self_destruct/Id' \"\$histfile\" 2>/dev/null" >> "$self_destruct_script"
    echo "    fi" >> "$self_destruct_script"
    echo "  done" >> "$self_destruct_script"
    echo "fi" >> "$self_destruct_script"
    
    # Clear command history from memory for current session
    echo "# Clear command history from memory" >> "$self_destruct_script"
    echo "history -c 2>/dev/null" >> "$self_destruct_script"
    echo "unset HISTFILE 2>/dev/null" >> "$self_destruct_script"
    echo "export HISTSIZE=0 2>/dev/null" >> "$self_destruct_script"
    
    # Remove temporary and backup files
    echo "# Remove any backup files or configs" >> "$self_destruct_script"
    echo "find /tmp -name 'logwipe*' -type f -exec rm -f {} \\; 2>/dev/null" >> "$self_destruct_script"
    echo "find /tmp -name 'recover_time.sh' -type f -exec rm -f {} \\; 2>/dev/null" >> "$self_destruct_script"
    echo "find /tmp -name '*_erase_*.sh' -type f | grep -v \"\$(basename \$0)\" | xargs rm -f 2>/dev/null" >> "$self_destruct_script"
    
    # Clean editor swap/backup files
    echo "# Clean editor backup/swap files" >> "$self_destruct_script"
    echo "find /tmp -name '.*.swp' -type f -exec rm -f {} \\; 2>/dev/null" >> "$self_destruct_script"
    echo "find /tmp -name '*~' -type f -exec rm -f {} \\; 2>/dev/null" >> "$self_destruct_script"
    
    # Make sure the main script directory is thoroughly removed
    echo "# Ensure main directory is completely removed" >> "$self_destruct_script"
    echo "if [ -d \"$real_script_dir\" ]; then" >> "$self_destruct_script"
    echo "  chmod -R 700 \"$real_script_dir\" 2>/dev/null # Ensure we have permissions to delete" >> "$self_destruct_script"
    echo "  rm -rf \"$real_script_dir\" 2>/dev/null" >> "$self_destruct_script"
    echo "  # Verify deletion" >> "$self_destruct_script"
    echo "  if [ -d \"$real_script_dir\" ]; then" >> "$self_destruct_script"
    echo "    echo \"Initial removal failed, trying more aggressive approach...\"" >> "$self_destruct_script"
    echo "    # More aggressive approach" >> "$self_destruct_script"
    echo "    find \"$real_script_dir\" -type f -exec rm -f {} \\; 2>/dev/null" >> "$self_destruct_script"
    echo "    find \"$real_script_dir\" -type d -empty -delete 2>/dev/null" >> "$self_destruct_script"
    echo "    # Try one more time with rm -rf" >> "$self_destruct_script"
    echo "    rm -rf \"$real_script_dir\" 2>/dev/null" >> "$self_destruct_script"
    echo "  fi" >> "$self_destruct_script"
    echo "fi" >> "$self_destruct_script"
    
    # Clean up any environment variables
    echo "# Remove any environment variables" >> "$self_destruct_script"
    echo "unset LOGWIPE_* 2>/dev/null" >> "$self_destruct_script"
    echo "unset LOG_WIPE_* 2>/dev/null" >> "$self_destruct_script"
    
    # Clean shell aliases
    echo "# Remove any shell aliases" >> "$self_destruct_script"
    echo "unalias logwipe 2>/dev/null" >> "$self_destruct_script"
    echo "unalias lw 2>/dev/null" >> "$self_destruct_script"
    
    # Clean up common locations where LogWipe might have left traces
    echo "# Clean common locations" >> "$self_destruct_script"
    echo "rm -f ~/.logwipe* 2>/dev/null" >> "$self_destruct_script"
    echo "rm -f ~/logwipe* 2>/dev/null" >> "$self_destruct_script"
    echo "rm -f ~/.config/logwipe* 2>/dev/null" >> "$self_destruct_script"
    
    # Clean bash sessions and recent commands
    echo "# Clean bash sessions" >> "$self_destruct_script"
    echo "if [ -d ~/.bash_sessions ]; then" >> "$self_destruct_script"
    echo "  find ~/.bash_sessions -type f -exec sed -i '/logwipe/Id' {} \\; 2>/dev/null" >> "$self_destruct_script"
    echo "fi" >> "$self_destruct_script"
    
    # Clean terminal scrollback
    echo "# Clear terminal scrollback" >> "$self_destruct_script"
    echo "clear" >> "$self_destruct_script"
    echo "printf '\\033[3J'" >> "$self_destruct_script"  # Clear scrollback
    
    # Clean any log files that might contain traces
    echo "# Clean traces from system logs" >> "$self_destruct_script"
    echo "if [ \"\$(id -u)\" = \"0\" ]; then" >> "$self_destruct_script"
    echo "  # If running as root, we can clean system logs" >> "$self_destruct_script"
    echo "  for log_file in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure; do" >> "$self_destruct_script"
    echo "    if [ -f \"\$log_file\" ]; then" >> "$self_destruct_script"
    echo "      sed -i '/logwipe/Id' \"\$log_file\" 2>/dev/null" >> "$self_destruct_script"
    echo "      sed -i '/LogWipe/Id' \"\$log_file\" 2>/dev/null" >> "$self_destruct_script"
    echo "    fi" >> "$self_destruct_script"
    echo "  done" >> "$self_destruct_script"
    echo "fi" >> "$self_destruct_script"
    
    # Overwrite free space in /tmp to eliminate traces
    echo "# Overwrite free space in /tmp" >> "$self_destruct_script"
    echo "dd if=/dev/zero of=/tmp/zeroes bs=1M count=10 2>/dev/null || true" >> "$self_destruct_script"
    echo "rm -f /tmp/zeroes 2>/dev/null" >> "$self_destruct_script"
    
    # Clean any process that might include LogWipe in its name or arguments (careful!)
    echo "# Clean process information, if possible" >> "$self_destruct_script"
    echo "# Note: This only works on processes owned by the current user" >> "$self_destruct_script"
    echo "pkill -f logwipe 2>/dev/null || true" >> "$self_destruct_script"
    
    # Add sleep to ensure all write operations are completed
    echo "# Allow time for all operations to complete" >> "$self_destruct_script"
    echo "sync" >> "$self_destruct_script"
    echo "sleep 3" >> "$self_destruct_script"
    
    # Finally remove the self-destruct script and exit
    echo "# Remove this script" >> "$self_destruct_script"
    echo "if [ -f \"\$0\" ]; then" >> "$self_destruct_script"
    echo "  rm -f \"\$0\" 2>/dev/null" >> "$self_destruct_script"
    echo "fi" >> "$self_destruct_script"
    echo "exit 0" >> "$self_destruct_script"
    
    # Make the script executable
    chmod +x "$self_destruct_script"
    
    # Begin secure file deletion process
    show_notification "Securely erasing LogWipe files..." "info"
    log_action "Initiated secure file deletion"
    
    # First, secure all sensitive files directly
    find "$real_script_dir" -type f -name "*.sh" -o -name "*.conf" -o -path "*/logs/*" | while read file; do
        if [ -f "$file" ]; then
            # Use shred if available
            if command -v shred >/dev/null 2>&1; then
                shred -u -z -n $passes "$file" 2>/dev/null
            else
                # Fallback method using dd
                dd if=/dev/urandom of="$file" bs=1k count=1 conv=notrunc >/dev/null 2>&1
                dd if=/dev/zero of="$file" bs=1k count=1 conv=notrunc >/dev/null 2>&1
                rm -f "$file" 2>/dev/null
            fi
        fi
    done
    
    # Schedule the self-destruct script to run after this process exits
    # We use several methods to ensure it runs
    (nohup "$self_destruct_script" >/dev/null 2>&1 &) &
    
    # Wait a moment to ensure the script has started
    sleep 1
    
    # Display final message
    echo -e "${RED}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║          LogWipe SELF-DESTRUCT INITIATED               ║${NC}"
    echo -e "${RED}║      All traces of LogWipe are being eliminated        ║${NC}"
    echo -e "${RED}║                                                        ║${NC}"
    echo -e "${RED}║  The tool will now be completely removed from system   ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════╝${NC}"
    
    # Pause to allow reading the message
    sleep 3
    
    # Clean terminal to remove visible traces of our message
    clear
    
    # Clear command history for this session
    history -c 2>/dev/null
    
    # Exit the main script
    exit 0
}

# Function to check if running in a virtual environment
is_virtual_env() {
    if [ -d "/proc/vz" ] || [ -d "/proc/bc" ]; then
        return 0
    elif grep -q "hypervisor" /proc/cpuinfo 2>/dev/null; then
        return 0
    elif [ -n "$(dmesg | grep -i "vmware\|virtualbox\|kvm\|xen")" ]; then
        return 0
    elif [ -n "$(lscpu | grep -i "Hypervisor")" ]; then
        return 0
    fi
    return 1
}

# Function to get system information
get_system_info() {
    echo "System Information:"
    echo "------------------"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "Distribution: $(lsb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null || echo "Unknown")"
    echo "Architecture: $(uname -m)"
    echo "CPU: $(grep "model name" /proc/cpuinfo | head -1 | cut -d ":" -f2 | sed 's/^[ \t]*//')"
    echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
    echo "Disk Space: $(df -h / | awk 'NR==2 {print $2}')"
    echo "Virtual Environment: $(is_virtual_env && echo "Yes" || echo "No")"
    echo "------------------"
    echo "Network Information:"
    echo "------------------"
    ip -4 addr show | grep -v 127.0.0.1 | grep "inet " | awk '{print $NF ": " $2}'
    echo "------------------"
    echo "Log Directory Size: $(du -sh /var/log 2>/dev/null | cut -f1)"
    
    log_action "System information displayed"
    
    echo ""
    read -p "Press Enter to continue..."
    return 0
}

# Function to check system requirements
check_requirements() {
    local requirements_met=true
    
    echo "Checking system requirements..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "Error: Not running as root"
        requirements_met=false
    else
        echo "✓ Running as root"
    fi
    
    # Check for required commands
    local required_commands=("date" "tar" "find" "grep" "journalctl" "ip")
    for cmd in "${required_commands[@]}"; do
        if command_exists "$cmd"; then
            echo "✓ $cmd is available"
        else
            echo "× $cmd is not available"
            requirements_met=false
        fi
    done
    
    # Check for write access to log directories
    if [ -w "/var/log" ]; then
        echo "✓ Write access to /var/log"
    else
        echo "× No write access to /var/log"
        requirements_met=false
    fi
    
    # Return result
    if [ "$requirements_met" = true ]; then
        echo "All requirements met!"
        return 0
    else
        echo "Some requirements not met. The tool may not function correctly."
        return 1
    fi
}

# Function to parse a config file into variables
parse_config() {
    local config_file="$1"
    if [ -f "$config_file" ]; then
        # Source the file
        source "$config_file"
        log_action "Loaded configuration from $config_file"
    else
        echo "Config file not found: $config_file"
        log_action "Config file not found: $config_file"
        return 1
    fi
    return 0
}

# Function to create a sample config file
create_sample_config() {
    local config_file="$1"
    if [ ! -f "$config_file" ]; then
        cat > "$config_file" << 'EOL'
# LogWipe Configuration File
# Configuration settings primarily affect fake log generation and verbosity.
# Most cleaning and analysis operations act directly on standard system paths.

# Log generation settings (Used by Fake Log Generator)
LOG_DENSITY="medium"
TIME_FRAME="24h"
REALISM_LEVEL="high"

# Application settings
VERBOSE_MODE=false

# Standard log paths - These will be validated at runtime
# If a path doesn't exist, the tool will fall back to a sensible default
SYSLOG_PATH="/var/log/syslog"
AUTH_LOG_PATH="/var/log/auth.log"
KERN_LOG_PATH="/var/log/kern.log"
APACHE_ACCESS_LOG_PATH="/var/log/apache2/access.log"
NGINX_ACCESS_LOG_PATH="/var/log/nginx/access.log"
MYSQL_ERROR_LOG_PATH="/var/log/mysql/error.log"

# Security level (standard, enhanced, maximum)
SECURITY_LEVEL="standard"
EOL
        echo "Created sample config file: $config_file"
        log_action "Created sample config file: $config_file"
    else
        echo "Config file already exists: $config_file"
    fi
}

# Function to safely remove files
safe_remove() {
    local path="$1"
    local force="${2:-false}"
    
    # Don't delete important system directories or files
    if [[ "$path" == "/" || "$path" == "/etc" || "$path" == "/bin" || "$path" == "/usr" || 
          "$path" == "/boot" || "$path" == "/dev" || "$path" == "/proc" || "$path" == "/sys" || 
          "$path" == "/var" || "$path" == "/home" || "$path" == "/root" || "$path" == "/lib" || 
          "$path" == "/lib64" || "$path" == "/mnt" || "$path" == "/opt" || "$path" == "/run" || 
          "$path" == "/sbin" || "$path" == "/tmp" || "$path" == "/media" ]]; then
        echo "Error: Attempting to delete critical system directory or file: $path"
        log_action "Error: Attempted to delete critical system directory or file: $path"
        return 1
    fi
    
    # Check if the path contains a wildcard and warn the user
    if [[ "$path" == *"*"* || "$path" == *"?"* || "$path" == *"["* ]]; then
        if [ "$force" != "true" ]; then
            show_notification "Warning: Path contains wildcard characters: $path" "warning"
            if ! confirm_action "Are you sure you want to proceed with deletion using wildcards?" "N"; then
                log_action "Deletion aborted: User canceled wildcard deletion for $path"
                return 1
            fi
        fi
    fi
    
    # Check if this is a potentially important config file
    if [[ "$path" == *".conf" || "$path" == *".config" || "$path" == *".cfg" || "$path" == *".ini" ]]; then
        if [ "$force" != "true" ]; then
            show_notification "Warning: This appears to be a configuration file: $path" "warning"
            if ! confirm_action "Are you sure you want to delete this configuration file?" "N"; then
                log_action "Deletion aborted: User canceled configuration file deletion for $path"
                return 1
            fi
        fi
    fi
    
    # Remove the file or directory with confirmation for directories
    if [ -d "$path" ]; then
        if [ "$force" != "true" ]; then
            local dir_size=$(du -sh "$path" 2>/dev/null | cut -f1)
            show_notification "Directory size: $dir_size" "warning"
            
            # Count files to prevent accidental large directory deletion
            local file_count=$(find "$path" -type f | wc -l)
            if [ "$file_count" -gt 50 ]; then
                show_notification "Directory contains $file_count files!" "warning"
                if ! confirm_action "Are you ABSOLUTELY sure you want to delete this entire directory?" "N"; then
                    log_action "Deletion aborted: User canceled large directory deletion for $path"
                    return 1
                fi
            else
                if ! confirm_action "Delete directory: $path?" "N"; then
                    log_action "Deletion aborted: User canceled directory deletion for $path"
                    return 1
                fi
            fi
        fi
        
        rm -rf "$path" 2>/dev/null && {
            log_action "Removed directory: $path"
            return 0
        } || {
            log_action "Failed to remove directory: $path"
            return 1
        }
    elif [ -f "$path" ]; then
        if [ "$force" != "true" ] && [ $(stat -c%s "$path") -gt 1048576 ]; then  # 1MB
            local file_size=$(du -h "$path" 2>/dev/null | cut -f1)
            show_notification "Large file detected: $file_size" "warning"
            if ! confirm_action "Delete file: $path?" "N"; then
                log_action "Deletion aborted: User canceled large file deletion for $path"
                return 1
            fi
        fi
        
        rm -f "$path" 2>/dev/null && {
            log_action "Removed file: $path"
            return 0
        } || {
            log_action "Failed to remove file: $path"
            return 1
        }
    else
        log_action "Path does not exist: $path"
        return 1
    fi
}

# Function to get current timestamp
get_timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

# Function to validate log paths from configuration
validate_log_paths() {
    # Check each configured log path and provide fallbacks if needed
    
    # Syslog path validation
    if [ ! -f "$SYSLOG_PATH" ]; then
        # Try common alternatives
        if [ -f "/var/log/messages" ]; then
            SYSLOG_PATH="/var/log/messages"
            log_action "Using alternative syslog path: $SYSLOG_PATH"
        elif [ -f "/var/log/syslog.log" ]; then
            SYSLOG_PATH="/var/log/syslog.log"
            log_action "Using alternative syslog path: $SYSLOG_PATH"
        fi
    fi
    
    # Auth log validation
    if [ ! -f "$AUTH_LOG_PATH" ]; then
        # Try common alternatives
        if [ -f "/var/log/secure" ]; then
            AUTH_LOG_PATH="/var/log/secure"
            log_action "Using alternative auth log path: $AUTH_LOG_PATH"
        elif [ -f "/var/log/auth.log.1" ]; then
            AUTH_LOG_PATH="/var/log/auth.log.1"
            log_action "Using alternative auth log path: $AUTH_LOG_PATH"
        fi
    fi
    
    # Kernel log validation
    if [ ! -f "$KERN_LOG_PATH" ]; then
        # Try common alternatives
        if [ -f "/var/log/dmesg" ]; then
            KERN_LOG_PATH="/var/log/dmesg"
            log_action "Using alternative kernel log path: $KERN_LOG_PATH"
        fi
    fi
    
    # Apache log validation
    if [ ! -f "$APACHE_ACCESS_LOG_PATH" ]; then
        # Try common alternatives
        if [ -f "/var/log/httpd/access_log" ]; then
            APACHE_ACCESS_LOG_PATH="/var/log/httpd/access_log"
            log_action "Using alternative Apache log path: $APACHE_ACCESS_LOG_PATH"
        elif [ -f "/var/log/apache/access.log" ]; then
            APACHE_ACCESS_LOG_PATH="/var/log/apache/access.log"
            log_action "Using alternative Apache log path: $APACHE_ACCESS_LOG_PATH"
        fi
    fi
    
    # Nginx log validation
    if [ ! -f "$NGINX_ACCESS_LOG_PATH" ]; then
        # Try common alternatives
        if [ -d "/var/log/nginx" ] && [ -f "$(find /var/log/nginx -name "*.log" | head -1)" ]; then
            NGINX_ACCESS_LOG_PATH="$(find /var/log/nginx -name "*.log" | head -1)"
            log_action "Using alternative Nginx log path: $NGINX_ACCESS_LOG_PATH"
        fi
    fi
    
    # MySQL log validation
    if [ ! -f "$MYSQL_ERROR_LOG_PATH" ]; then
        # Try common alternatives
        if [ -f "/var/log/mysql.log" ]; then
            MYSQL_ERROR_LOG_PATH="/var/log/mysql.log"
            log_action "Using alternative MySQL log path: $MYSQL_ERROR_LOG_PATH"
        elif [ -f "/var/log/mysql.err" ]; then
            MYSQL_ERROR_LOG_PATH="/var/log/mysql.err"
            log_action "Using alternative MySQL log path: $MYSQL_ERROR_LOG_PATH"
        fi
    fi
} 