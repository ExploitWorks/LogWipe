#!/bin/bash

# Attribution Cleaner Module for LogWipe
# Eliminates traces that could be used for behavioral analysis and attacker attribution

# Function to clean command line timing patterns
clean_timing_patterns() {
    show_notification "Cleaning command timing patterns..." "info"
    log_action "Started cleaning command timing patterns"
    
    # Clean bash command history timestamps if they exist
    if command_exists find; then
        # Look for bash_history files with timestamp option enabled (format: #time_stamp_pattern)
        find /home -name ".bash_history" -type f -exec grep -l "^#[0-9]" {} \; 2>/dev/null | while read histfile; do
            if confirm_action "Found timestamped history in $histfile. Remove timestamps?" "Y"; then
                # Create a temporary file without timestamps
                local temp_file=$(mktemp)
                grep -v "^#[0-9]" "$histfile" > "$temp_file"
                
                # Replace original file
                cat "$temp_file" > "$histfile"
                rm -f "$temp_file"
                
                log_action "Removed timestamp patterns from $histfile"
                show_notification "Timestamp patterns removed from $histfile" "success"
            fi
        done
    fi
    
    # Disable history timestamps for future sessions
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            username=$(basename "$user_home")
            
            # Check if .bashrc exists
            if [ -f "$user_home/.bashrc" ]; then
                # Check if HISTTIMEFORMAT is set
                if grep -q "HISTTIMEFORMAT" "$user_home/.bashrc"; then
                    if confirm_action "Remove HISTTIMEFORMAT for user $username?" "Y"; then
                        # Comment out any HISTTIMEFORMAT lines
                        sed -i 's/^\(export \)\?HISTTIMEFORMAT/# \1HISTTIMEFORMAT/g' "$user_home/.bashrc"
                        log_action "Disabled history timestamps for user $username"
                        show_notification "Disabled history timestamps for user $username" "success"
                    fi
                fi
            fi
        fi
    done
    
    # Also check root's bashrc
    if [ -f "/root/.bashrc" ] && grep -q "HISTTIMEFORMAT" "/root/.bashrc"; then
        if confirm_action "Remove HISTTIMEFORMAT for root?" "Y"; then
            # Comment out any HISTTIMEFORMAT lines
            sed -i 's/^\(export \)\?HISTTIMEFORMAT/# \1HISTTIMEFORMAT/g' "/root/.bashrc"
            log_action "Disabled history timestamps for root"
            show_notification "Disabled history timestamps for root" "success"
        fi
    fi
    
    # Disable lastlog-based timing analysis
    if [ -f "/var/log/lastlog" ]; then
        if confirm_action "Clear lastlog to remove login timing patterns?" "Y"; then
            cat /dev/null > /var/log/lastlog 2>/dev/null
            log_action "Cleared lastlog to remove timing patterns"
            show_notification "Lastlog cleared to remove timing patterns" "success"
        fi
    fi
    
    # Disable wtmp-based timing analysis
    if [ -f "/var/log/wtmp" ]; then
        if confirm_action "Clear wtmp to remove login timing patterns?" "Y"; then
            cat /dev/null > /var/log/wtmp 2>/dev/null
            log_action "Cleared wtmp to remove timing patterns"
            show_notification "Wtmp cleared to remove timing patterns" "success"
        fi
    fi
    
    return 0
}

# Function to clean geographical attribution hints
clean_geo_traces() {
    show_notification "Cleaning geographical attribution traces..." "info"
    log_action "Started cleaning geographical attribution traces"
    
    # Clean timezone data which might reveal attacker's location
    if [ -f "/etc/localtime" ] && [ -f "/etc/timezone" ]; then
        # Show current timezone
        current_tz=$(cat /etc/timezone 2>/dev/null || readlink /etc/localtime 2>/dev/null | sed 's/.*zoneinfo\///')
        show_notification "Current system timezone: $current_tz" "info"
        
        if confirm_action "Would you like to modify timezone settings to avoid geographical attribution?" "Y"; then
            echo -e "${YELLOW}Common timezone options:${NC}"
            echo -e "1. ${WHITE}UTC${NC} (Universal Time, neutral)"
            echo -e "2. ${WHITE}US/Eastern${NC} (Eastern US timezone)"
            echo -e "3. ${WHITE}Europe/London${NC} (UK timezone)"
            echo -e "4. ${WHITE}Asia/Singapore${NC} (Singapore timezone)"
            
            read -p "$(echo -e "${YELLOW}Select timezone [1-4] or enter custom timezone:${NC} ")" tz_choice
            
            case $tz_choice in
                1) new_tz="UTC" ;;
                2) new_tz="US/Eastern" ;;
                3) new_tz="Europe/London" ;;
                4) new_tz="Asia/Singapore" ;;
                *) new_tz="$tz_choice" ;;
            esac
            
            # Verify the timezone is valid
            if [ -f "/usr/share/zoneinfo/$new_tz" ]; then
                # Set the timezone
                ln -sf "/usr/share/zoneinfo/$new_tz" /etc/localtime
                echo "$new_tz" > /etc/timezone
                
                log_action "Changed timezone from $current_tz to $new_tz"
                show_notification "Timezone changed to $new_tz" "success"
            else
                show_notification "Invalid timezone: $new_tz" "error"
                log_action "Failed to change timezone: invalid timezone $new_tz"
            fi
        fi
    fi
    
    # Clean locale settings which might reveal language/region
    if [ -f "/etc/default/locale" ]; then
        # Show current locale
        current_locale=$(grep "LANG=" /etc/default/locale 2>/dev/null | cut -d= -f2)
        show_notification "Current system locale: $current_locale" "info"
        
        if confirm_action "Would you like to modify locale settings to avoid linguistic attribution?" "Y"; then
            echo -e "${YELLOW}Common locale options:${NC}"
            echo -e "1. ${WHITE}en_US.UTF-8${NC} (US English)"
            echo -e "2. ${WHITE}en_GB.UTF-8${NC} (British English)"
            echo -e "3. ${WHITE}C.UTF-8${NC} (Neutral locale)"
            
            read -p "$(echo -e "${YELLOW}Select locale [1-3] or enter custom locale:${NC} ")" locale_choice
            
            case $locale_choice in
                1) new_locale="en_US.UTF-8" ;;
                2) new_locale="en_GB.UTF-8" ;;
                3) new_locale="C.UTF-8" ;;
                *) new_locale="$locale_choice" ;;
            esac
            
            # Update locale
            echo "LANG=$new_locale" > /etc/default/locale
            
            log_action "Changed locale from $current_locale to $new_locale"
            show_notification "Locale changed to $new_locale" "success"
        fi
    fi
    
    # Look for IP geolocation in log files
    if command_exists grep; then
        show_notification "Scanning log files for IP addresses that could reveal location..." "info"
        
        # Find log files with IP addresses
        find /var/log -type f -name "*.log" -exec grep -l -E "([0-9]{1,3}\.){3}[0-9]{1,3}" {} \; 2>/dev/null | while read logfile; do
            if confirm_action "Log file $logfile contains IP addresses. Clean it?" "Y"; then
                # Remove or sanitize IP addresses
                local temp_file=$(mktemp)
                sed -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}/0.0.0.0/g' "$logfile" > "$temp_file"
                cat "$temp_file" > "$logfile"
                rm -f "$temp_file"
                
                log_action "Sanitized IP addresses in $logfile"
                show_notification "IP addresses sanitized in $logfile" "success"
            fi
        done
    fi
    
    return 0
}

# Function to clean writing style patterns
clean_writing_patterns() {
    show_notification "Cleaning writing style patterns..." "info"
    log_action "Started cleaning writing style patterns"
    
    # Scan for typos and common writing patterns in config files and scripts
    if command_exists find; then
        show_notification "Scanning for writing patterns in custom files..." "info"
        
        # Look for comment patterns in scripts that might reveal writing style
        find /home -type f -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.conf" 2>/dev/null | while read scriptfile; do
            # Check if file contains comments
            if grep -q "^#" "$scriptfile" 2>/dev/null; then
                if confirm_action "File $scriptfile contains comments that may reveal writing style. View and edit?" "N"; then
                    # Display comments
                    echo -e "${YELLOW}Comments in $scriptfile:${NC}"
                    grep "^#" "$scriptfile" | head -10
                    
                    if confirm_action "Remove all comments from this file?" "N"; then
                        # Remove comments (keeping shebang line if present)
                        local temp_file=$(mktemp)
                        awk 'NR==1 && /^#!/{print; next} /^#/{next} {print}' "$scriptfile" > "$temp_file"
                        cat "$temp_file" > "$scriptfile"
                        rm -f "$temp_file"
                        
                        log_action "Removed comments from $scriptfile"
                        show_notification "Comments removed from $scriptfile" "success"
                    fi
                fi
            fi
        done
    fi
    
    # Look for README, documentation, or note files that could contain writing style
    find /home -type f -name "README*" -o -name "*.md" -o -name "*.txt" -o -name "notes*" 2>/dev/null | while read textfile; do
        if confirm_action "File $textfile may contain writing style patterns. Review?" "N"; then
            # Show the first few lines
            echo -e "${YELLOW}Content of $textfile:${NC}"
            head -5 "$textfile"
            
            if confirm_action "Would you like to remove this file?" "N"; then
                rm -f "$textfile"
                log_action "Removed text file $textfile that could reveal writing style"
                show_notification "Removed $textfile" "success"
            fi
        fi
    done
    
    return 0
}

# Function to clean keyboard and command patterns
clean_keyboard_patterns() {
    show_notification "Cleaning keyboard and command patterns..." "info"
    log_action "Started cleaning keyboard and command patterns"
    
    # Clean command patterns from bash history
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            username=$(basename "$user_home")
            
            # Check bash_history for unique command patterns
            if [ -f "$user_home/.bash_history" ]; then
                # Check for frequently used aliases or custom commands
                local custom_cmds=$(grep -v "^#" "$user_home/.bash_history" | sort | uniq -c | sort -nr | head -10)
                
                if [ -n "$custom_cmds" ]; then
                    echo -e "${YELLOW}Frequent command patterns for user $username:${NC}"
                    echo "$custom_cmds"
                    
                    if confirm_action "Randomize command history to eliminate patterns?" "Y"; then
                        # Create a shuffled history file
                        local temp_file=$(mktemp)
                        grep -v "^#" "$user_home/.bash_history" | shuf > "$temp_file"
                        cat "$temp_file" > "$user_home/.bash_history"
                        rm -f "$temp_file"
                        
                        log_action "Randomized command history for user $username to eliminate patterns"
                        show_notification "Command history randomized for user $username" "success"
                    fi
                fi
            fi
            
            # Check for custom aliases that might reveal patterns
            if [ -f "$user_home/.bashrc" ] || [ -f "$user_home/.bash_aliases" ]; then
                local alias_files=()
                [ -f "$user_home/.bashrc" ] && alias_files+=("$user_home/.bashrc")
                [ -f "$user_home/.bash_aliases" ] && alias_files+=("$user_home/.bash_aliases")
                
                for alias_file in "${alias_files[@]}"; do
                    if grep -q "^alias " "$alias_file"; then
                        echo -e "${YELLOW}Custom aliases in $alias_file:${NC}"
                        grep "^alias " "$alias_file" | head -10
                        
                        if confirm_action "Remove custom aliases from $alias_file?" "N"; then
                            # Comment out aliases
                            sed -i 's/^alias /# alias /g' "$alias_file"
                            
                            log_action "Commented out custom aliases in $alias_file"
                            show_notification "Custom aliases commented out in $alias_file" "success"
                        fi
                    fi
                done
            fi
        fi
    done
    
    # Check for common typos in command history (might reveal typing patterns)
    for user_home in /home/*; do
        if [ -d "$user_home" ] && [ -f "$user_home/.bash_history" ]; then
            username=$(basename "$user_home")
            
            # Common typo patterns
            local typos=$(grep -E "sl$|gerp|hsitroy|cta |sodu|pdw" "$user_home/.bash_history" 2>/dev/null)
            
            if [ -n "$typos" ]; then
                echo -e "${YELLOW}Possible typing pattern detected for user $username:${NC}"
                echo "$typos" | head -5
                
                if confirm_action "Remove these commands from history?" "Y"; then
                    local temp_file=$(mktemp)
                    grep -v -E "sl$|gerp|hsitroy|cta |sodu|pdw" "$user_home/.bash_history" > "$temp_file"
                    cat "$temp_file" > "$user_home/.bash_history"
                    rm -f "$temp_file"
                    
                    log_action "Removed commands with typing patterns from $username's history"
                    show_notification "Commands with typing patterns removed" "success"
                fi
            fi
        fi
    done
    
    return 0
}

# Function to clean tool usage patterns and versions
clean_tool_patterns() {
    show_notification "Cleaning tool usage patterns and versions..." "info"
    log_action "Started cleaning tool usage patterns"
    
    # Check for unique tool versions that might be used for attribution
    if command_exists dpkg || command_exists rpm; then
        show_notification "Checking for unique or uncommon package versions..." "info"
        
        local pkg_list=""
        if command_exists dpkg; then
            # Debian-based system
            pkg_list=$(dpkg -l | grep -E "pentesting|security|hacking|crack|exploit|recon" | awk '{print $2 " (" $3 ")"}')
        elif command_exists rpm; then
            # Red Hat-based system
            pkg_list=$(rpm -qa | grep -E "pentesting|security|hacking|crack|exploit|recon" | sort)
        fi
        
        if [ -n "$pkg_list" ]; then
            echo -e "${YELLOW}Potentially attributable security tools:${NC}"
            echo "$pkg_list" | head -10
            
            if confirm_action "Would you like to see options for managing these tools?" "Y"; then
                echo -e "${YELLOW}Options for tool management:${NC}"
                echo -e "1. ${WHITE}Keep tools but remove from package database${NC}"
                echo -e "2. ${WHITE}Remove tools completely${NC}"
                echo -e "3. ${WHITE}No action${NC}"
                
                read -p "$(echo -e "${YELLOW}Select option [1-3]:${NC} ")" tool_action
                
                case $tool_action in
                    1)
                        show_notification "This action requires careful handling and is best performed manually" "warning"
                        log_action "User advised about manual package database manipulation"
                        ;;
                    2)
                        if confirm_action "This will remove the listed security tools. Continue?" "N"; then
                            if command_exists dpkg; then
                                dpkg -l | grep -E "pentesting|security|hacking|crack|exploit|recon" | awk '{print $2}' | xargs apt-get -y remove 2>/dev/null
                            elif command_exists rpm; then
                                rpm -qa | grep -E "pentesting|security|hacking|crack|exploit|recon" | xargs rpm -e 2>/dev/null
                            fi
                            log_action "Removed attributable security tools"
                            show_notification "Security tools removed" "success"
                        fi
                        ;;
                    *)
                        show_notification "No action taken" "info"
                        ;;
                esac
            fi
        else
            show_notification "No obvious security tools found in package database" "info"
        fi
    fi
    
    # Check for shell configuration that could reveal tool usage patterns
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            username=$(basename "$user_home")
            
            # Inspect for tool-specific customizations
            local config_files=("$user_home/.bashrc" "$user_home/.zshrc" "$user_home/.profile")
            
            for config_file in "${config_files[@]}"; do
                if [ -f "$config_file" ]; then
                    # Look for tool-specific configurations
                    local tool_configs=$(grep -E "alias|export|PATH=.*bin|source.*completion" "$config_file" | grep -E "nmap|metasploit|burp|wireshark|sqlmap")
                    
                    if [ -n "$tool_configs" ]; then
                        echo -e "${YELLOW}Tool-specific configurations in $config_file:${NC}"
                        echo "$tool_configs" | head -5
                        
                        if confirm_action "Remove these tool-specific configurations?" "Y"; then
                            # Comment out tool configurations
                            local temp_file=$(mktemp)
                            sed -E 's/^(.*)(nmap|metasploit|burp|wireshark|sqlmap)(.*)/# \1\2\3/g' "$config_file" > "$temp_file"
                            cat "$temp_file" > "$config_file"
                            rm -f "$temp_file"
                            
                            log_action "Commented out tool-specific configurations in $config_file"
                            show_notification "Tool configurations commented out in $config_file" "success"
                        fi
                    fi
                fi
            done
        fi
    done
    
    return 0
}

# Function to clean custom malware and backdoor signatures
clean_malware_signatures() {
    show_notification "Cleaning custom malware and backdoor signatures..." "info"
    log_action "Started cleaning malware signatures"
    
    # Scan for common backdoor patterns
    show_notification "Scanning for backdoor patterns..." "info"
    
    # Check for common webshells
    find /var/www -type f -name "*.php" -exec grep -l -E "eval.*base64_decode|system.*_REQUEST|shell_exec.*_GET" {} \; 2>/dev/null | while read backdoor; do
        echo -e "${YELLOW}Potential webshell found: $backdoor${NC}"
        
        if confirm_action "Would you like to remove this file?" "Y"; then
            rm -f "$backdoor"
            log_action "Removed webshell backdoor: $backdoor"
            show_notification "Removed webshell: $backdoor" "success"
        elif confirm_action "Would you like to obfuscate this file instead?" "N"; then
            # Basic obfuscation by encoding functions
            local temp_file=$(mktemp)
            sed -E 's/(eval|system|shell_exec|passthru|exec)/base64_decode("'.$(echo -n '\1' | base64).'")/' "$backdoor" > "$temp_file"
            cat "$temp_file" > "$backdoor"
            rm -f "$temp_file"
            
            log_action "Obfuscated webshell backdoor: $backdoor"
            show_notification "Obfuscated webshell: $backdoor" "success"
        fi
    done
    
    # Look for persistence mechanisms
    local persistence_paths=(
        "/etc/crontab"
        "/var/spool/cron"
        "/etc/cron.d"
        "/etc/init.d"
        "/etc/systemd/system"
        "/etc/rc.local"
    )
    
    for path in "${persistence_paths[@]}"; do
        if [ -e "$path" ]; then
            show_notification "Checking $path for persistence mechanisms..." "info"
            
            if [ -d "$path" ]; then
                find "$path" -type f -exec grep -l -E "nc |netcat|bash -i|bash -c|python -c|curl.*\| bash|wget.*\| bash" {} \; 2>/dev/null | while read file; do
                    echo -e "${YELLOW}Potential persistence mechanism found in $file${NC}"
                    grep -E "nc |netcat|bash -i|bash -c|python -c|curl.*\| bash|wget.*\| bash" "$file" | head -3
                    
                    if confirm_action "Remove this persistence mechanism?" "Y"; then
                        # Remove the suspicious lines
                        local temp_file=$(mktemp)
                        grep -v -E "nc |netcat|bash -i|bash -c|python -c|curl.*\| bash|wget.*\| bash" "$file" > "$temp_file"
                        cat "$temp_file" > "$file"
                        rm -f "$temp_file"
                        
                        log_action "Removed persistence mechanism from $file"
                        show_notification "Persistence mechanism removed from $file" "success"
                    elif confirm_action "Would you like to obfuscate it instead?" "N"; then
                        # Replace with a more subtle equivalent
                        local temp_file=$(mktemp)
                        sed -E 's/(nc |netcat|bash -i|bash -c|python -c|curl.*\| bash|wget.*\| bash)/# Legitimate maintenance task/' "$file" > "$temp_file"
                        cat "$temp_file" > "$file"
                        rm -f "$temp_file"
                        
                        log_action "Obfuscated persistence mechanism in $file"
                        show_notification "Persistence mechanism obfuscated in $file" "success"
                    fi
                done
            elif [ -f "$path" ]; then
                if grep -q -E "nc |netcat|bash -i|bash -c|python -c|curl.*\| bash|wget.*\| bash" "$path" 2>/dev/null; then
                    echo -e "${YELLOW}Potential persistence mechanism found in $path${NC}"
                    grep -E "nc |netcat|bash -i|bash -c|python -c|curl.*\| bash|wget.*\| bash" "$path" | head -3
                    
                    if confirm_action "Remove this persistence mechanism?" "Y"; then
                        # Remove the suspicious lines
                        local temp_file=$(mktemp)
                        grep -v -E "nc |netcat|bash -i|bash -c|python -c|curl.*\| bash|wget.*\| bash" "$path" > "$temp_file"
                        cat "$temp_file" > "$path"
                        rm -f "$temp_file"
                        
                        log_action "Removed persistence mechanism from $path"
                        show_notification "Persistence mechanism removed from $path" "success"
                    fi
                fi
            fi
        fi
    done
    
    # Clean SSH keys and authorized_keys files that could be linked to attacker
    for user_home in /home/*; do
        if [ -d "$user_home/.ssh" ]; then
            username=$(basename "$user_home")
            
            # Check for non-standard SSH keys
            find "$user_home/.ssh" -name "id_*" ! -name "id_rsa" ! -name "id_rsa.pub" ! -name "id_ed25519" ! -name "id_ed25519.pub" 2>/dev/null | while read key_file; do
                echo -e "${YELLOW}Non-standard SSH key found: $key_file${NC}"
                
                if confirm_action "Remove this SSH key?" "Y"; then
                    rm -f "$key_file"
                    log_action "Removed non-standard SSH key: $key_file"
                    show_notification "Removed SSH key: $key_file" "success"
                fi
            done
            
            # Check for multiple entries in authorized_keys
            if [ -f "$user_home/.ssh/authorized_keys" ]; then
                local key_count=$(grep -c "ssh-" "$user_home/.ssh/authorized_keys")
                
                if [ "$key_count" -gt 1 ]; then
                    echo -e "${YELLOW}Multiple SSH keys found in authorized_keys for user $username${NC}"
                    
                    if confirm_action "Review and clean authorized_keys?" "Y"; then
                        echo -e "${YELLOW}Current keys in authorized_keys:${NC}"
                        cat "$user_home/.ssh/authorized_keys"
                        
                        if confirm_action "Remove all keys except the first one?" "Y"; then
                            head -1 "$user_home/.ssh/authorized_keys" > "$user_home/.ssh/authorized_keys.new"
                            mv "$user_home/.ssh/authorized_keys.new" "$user_home/.ssh/authorized_keys"
                            
                            log_action "Removed additional SSH keys from $user_home/.ssh/authorized_keys"
                            show_notification "Kept only one SSH key in authorized_keys" "success"
                        fi
                    fi
                fi
            fi
        fi
    done
    
    return 0
}

# Function to handle behavioral analysis and attribution cleaner
handle_attribution_cleaning() {
    clear
    display_section_header "Behavioral & Attribution Trace Elimination"
    
    local options=(
        "Clean Command Timing Patterns"
        "Clean Geographical Attribution Traces"
        "Clean Writing Style Patterns"
        "Clean Keyboard & Command Patterns"
        "Clean Tool Usage & Version Patterns"
        "Clean Malware & Backdoor Signatures"
        "Complete Attribution Cleaning (All of the Above)"
        "Return to Main Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" choice

    case $choice in
        1) 
            clean_timing_patterns
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_attribution_cleaning
            ;;
        2) 
            clean_geo_traces
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_attribution_cleaning
            ;;
        3) 
            clean_writing_patterns
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_attribution_cleaning
            ;;
        4) 
            clean_keyboard_patterns
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_attribution_cleaning
            ;;
        5) 
            clean_tool_patterns
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_attribution_cleaning
            ;;
        6) 
            clean_malware_signatures
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_attribution_cleaning
            ;;
        7)
            # Execute all cleaning functions
            show_notification "Starting comprehensive attribution cleaning..." "info"
            clean_timing_patterns
            clean_geo_traces
            clean_writing_patterns
            clean_keyboard_patterns
            clean_tool_patterns
            clean_malware_signatures
            show_notification "Comprehensive attribution cleaning completed" "success"
            
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_attribution_cleaning
            ;;
        8) return 0 ;;
        *)
            show_notification "Invalid option" "error"
            sleep 1
            handle_attribution_cleaning
            ;;
    esac
} 