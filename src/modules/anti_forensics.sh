#!/bin/bash

# Anti-forensics module for LogWipe

# Function to securely sanitize specific entries in logs
sanitize_log_entries() {
    local pattern="$1"
    local log_file="$2"
    
    show_notification "Sanitizing specific entries in $log_file..." "info"
    log_action "Started sanitizing specific entries in $log_file"
    
    # Verify log file exists
    if [ ! -f "$log_file" ]; then
        show_notification "Error: Log file not found: $log_file" "error"
        log_action "Error: Log file not found: $log_file"
        return 1
    fi
    
    # Verify log file is writable
    if [ ! -w "$log_file" ]; then
        show_notification "Error: Log file not writable: $log_file" "error"
        log_action "Error: Log file not writable: $log_file"
        return 1
    fi
    
    # Create a temporary file
    local temp_file=$(mktemp)
    
    # Filter out entries containing the pattern
    grep -v "$pattern" "$log_file" > "$temp_file"
    
    # Replace the original file with the filtered content
    cat "$temp_file" > "$log_file"
    
    # Securely remove the temporary file
    shred -u "$temp_file" 2>/dev/null || rm -f "$temp_file"
    
    show_notification "Sanitized specific entries in $log_file" "success"
    log_action "Completed sanitizing specific entries in $log_file"
    return 0
}

# Function to manipulate timestamp on a file
manipulate_timestamp() {
    local file="$1"
    local reference_file="$2"
    
    show_notification "Manipulating timestamp on $file..." "info"
    log_action "Started manipulating timestamp on $file"
    
    # Verify file exists
    if [ ! -f "$file" ]; then
        show_notification "Error: File not found: $file" "error"
        log_action "Error: File not found: $file"
        return 1
    fi
    
    if [ -n "$reference_file" ]; then
        # Use reference file's timestamp
        if [ ! -f "$reference_file" ]; then
            show_notification "Error: Reference file not found: $reference_file" "error"
            log_action "Error: Reference file not found: $reference_file"
            return 1
        fi
        
        # Get timestamp from reference file
        local access_time=$(stat -c %X "$reference_file")
        local mod_time=$(stat -c %Y "$reference_file")
        
        # Apply timestamp to target file
        touch -a -d "@$access_time" "$file"
        touch -m -d "@$mod_time" "$file"
    else
        # Use random timestamp within a plausible range
        # Random time within the last 30 days
        local current_time=$(date +%s)
        local random_offset=$((RANDOM % 2592000)) # 30 days in seconds
        local random_time=$((current_time - random_offset))
        
        # Apply random timestamp
        touch -a -d "@$random_time" "$file"
        touch -m -d "@$random_time" "$file"
    fi
    
    show_notification "Successfully manipulated timestamp on $file" "success"
    log_action "Completed manipulating timestamp on $file"
    return 0
}

# Function to hide specific events within a time range
hide_time_range() {
    local log_file="$1"
    local start_time="$2"
    local end_time="$3"
    
    show_notification "Hiding events in time range from $log_file..." "info"
    log_action "Started hiding events in time range from $log_file"
    
    # Verify log file exists
    if [ ! -f "$log_file" ]; then
        show_notification "Error: Log file not found: $log_file" "error"
        log_action "Error: Log file not found: $log_file"
        return 1
    fi
    
    # Create a temporary file
    local temp_file=$(mktemp)
    
    # Convert log timestamp format to comparable format and filter
    if [[ "$log_file" == *"auth.log"* || "$log_file" == *"syslog"* ]]; then
        # For syslog and auth.log format (e.g., "Jul 15 21:30:45")
        awk -v s="$start_time" -v e="$end_time" '
        function parse_time(t) {
            cmd = "date -d \"" t "\" +%s"
            cmd | getline ts
            close(cmd)
            return ts
        }
        {
            # Extract timestamp from beginning of line
            ts = substr($0, 1, 15)
            # Only include lines outside the time range
            if (ts == "" || parse_time(ts) < parse_time(s) || parse_time(ts) > parse_time(e))
                print $0
        }' "$log_file" > "$temp_file"
    elif [[ "$log_file" == *"mysql"* ]]; then
        # For MySQL error log format (e.g., "2023-07-15 21:30:45")
        awk -v s="$start_time" -v e="$end_time" '
        function parse_time(t) {
            cmd = "date -d \"" t "\" +%s"
            cmd | getline ts
            close(cmd)
            return ts
        }
        {
            # Extract timestamp from beginning of line
            ts = substr($0, 1, 19)
            # Only include lines outside the time range
            if (ts == "" || parse_time(ts) < parse_time(s) || parse_time(ts) > parse_time(e))
                print $0
        }' "$log_file" > "$temp_file"
    elif [[ "$log_file" == *"access.log"* ]]; then
        # For web server access logs (e.g., "[15/Jul/2023:21:30:45 +0000]")
        awk -v s="$start_time" -v e="$end_time" '
        function parse_time(t) {
            # Extract date part from [...] format
            gsub(/[\[\]]/, "", t)
            cmd = "date -d \"" t "\" +%s"
            cmd | getline ts
            close(cmd)
            return ts
        }
        {
            # Find timestamp within square brackets
            match($0, /\[[^]]+\]/)
            if (RSTART > 0) {
                ts = substr($0, RSTART, RLENGTH)
                if (parse_time(ts) < parse_time(s) || parse_time(ts) > parse_time(e))
                    print $0
            } else {
                print $0
            }
        }' "$log_file" > "$temp_file"
    else
        # For unknown formats, attempt simple filtering
        grep -v -E "$(date -d "$start_time" +"%b %d|%Y-%m-%d")" "$log_file" | 
        grep -v -E "$(date -d "$end_time" +"%b %d|%Y-%m-%d")" > "$temp_file"
    fi
    
    # Replace the original file with the filtered content
    cat "$temp_file" > "$log_file"
    
    # Securely remove the temporary file
    shred -u "$temp_file" 2>/dev/null || rm -f "$temp_file"
    
    show_notification "Successfully removed events in time range from $log_file" "success"
    log_action "Completed hiding events in time range from $log_file"
    return 0
}

# Function to selectively edit log entries
edit_log_entries() {
    local log_file="$1"
    local search_pattern="$2"
    local replacement="$3"
    
    show_notification "Editing log entries in $log_file..." "info"
    log_action "Started editing log entries in $log_file"
    
    # Verify log file exists
    if [ ! -f "$log_file" ]; then
        show_notification "Error: Log file not found: $log_file" "error"
        log_action "Error: Log file not found: $log_file"
        return 1
    fi
    
    # Create a temporary file
    local temp_file=$(mktemp)
    
    # Perform the replacement
    sed "s/$search_pattern/$replacement/g" "$log_file" > "$temp_file"
    
    # Replace the original file with the edited content
    cat "$temp_file" > "$log_file"
    
    # Securely remove the temporary file
    shred -u "$temp_file" 2>/dev/null || rm -f "$temp_file"
    
    show_notification "Successfully edited log entries in $log_file" "success"
    log_action "Completed editing log entries in $log_file"
    return 0
}

# Function to randomize timestamps in a file
randomize_timestamps() {
    local log_file="$1"
    local time_variance="${2:-3600}"  # Default 1 hour variance
    
    show_notification "Randomizing timestamps in $log_file..." "info"
    log_action "Started randomizing timestamps in $log_file"
    
    # Verify log file exists
    if [ ! -f "$log_file" ]; then
        show_notification "Error: Log file not found: $log_file" "error"
        log_action "Error: Log file not found: $log_file"
        return 1
    fi
    
    # Create a temporary file
    local temp_file=$(mktemp)
    
    # Process different log formats
    if [[ "$log_file" == *"auth.log"* || "$log_file" == *"syslog"* ]]; then
        # For syslog and auth.log format (e.g., "Jul 15 21:30:45")
        awk -v variance="$time_variance" '
        function randomize_time(timestamp) {
            # Extract time components
            cmd = "date -d \"" timestamp "\" +\"%b %d %H:%M:%S\""
            cmd | getline formatted
            close(cmd)
            
            # Get epoch time
            cmd = "date -d \"" timestamp "\" +%s"
            cmd | getline epoch
            close(cmd)
            
            # Add random variance (-variance to +variance)
            random_offset = int(rand() * variance * 2) - variance
            new_epoch = epoch + random_offset
            
            # Convert back to formatted time
            cmd = "date -d @" new_epoch " +\"%b %d %H:%M:%S\""
            cmd | getline new_time
            close(cmd)
            
            return new_time
        }
        {
            if (NF >= 3) {
                # Extract timestamp from beginning of line
                timestamp = $1 " " $2 " " $3
                new_time = randomize_time(timestamp)
                
                # Replace timestamp in the line
                $1 = substr(new_time, 1, 3)
                $2 = substr(new_time, 5, 2)
                $3 = substr(new_time, 8)
            }
            print $0
        }' "$log_file" > "$temp_file"
    elif [[ "$log_file" == *"mysql"* ]]; then
        # For MySQL error log format (e.g., "2023-07-15 21:30:45")
        awk -v variance="$time_variance" '
        function randomize_time(timestamp) {
            # Get epoch time
            cmd = "date -d \"" timestamp "\" +%s"
            cmd | getline epoch
            close(cmd)
            
            # Add random variance (-variance to +variance)
            random_offset = int(rand() * variance * 2) - variance
            new_epoch = epoch + random_offset
            
            # Convert back to formatted time
            cmd = "date -d @" new_epoch " +\"%Y-%m-%d %H:%M:%S\""
            cmd | getline new_time
            close(cmd)
            
            return new_time
        }
        {
            if (length($0) >= 19) {
                # Extract timestamp from beginning of line
                timestamp = substr($0, 1, 19)
                new_time = randomize_time(timestamp)
                
                # Replace timestamp in the line
                $0 = new_time substr($0, 20)
            }
            print $0
        }' "$log_file" > "$temp_file"
    elif [[ "$log_file" == *"access.log"* ]]; then
        # For web server access logs (e.g., "192.168.1.1 - - [15/Jul/2023:21:30:45 +0000]")
        perl -pe '
        BEGIN { srand(); }
        if (m/(\[)([^]]+)(\])/) {
            my $pre = $1;
            my $timestamp = $2;
            my $post = $3;
            my $cmd = "date -d \"$timestamp\" +%s";
            my $epoch = `$cmd`;
            chomp($epoch);
            my $variance = '"$time_variance"';
            my $random_offset = int(rand() * $variance * 2) - $variance;
            my $new_epoch = $epoch + $random_offset;
            my $format_cmd = "date -d @$new_epoch \"+%d/%b/%Y:%H:%M:%S %z\"";
            my $new_timestamp = `$format_cmd`;
            chomp($new_timestamp);
            s/\Q$pre$timestamp$post\E/$pre$new_timestamp$post/;
        }' "$log_file" > "$temp_file"
    else
        # For unknown formats, skip
        show_notification "Unknown log format, skipping randomization" "warning"
        log_action "Unknown log format, skipped randomization for $log_file"
        rm -f "$temp_file"
        return 1
    fi
    
    # Replace the original file with the randomized content
    cat "$temp_file" > "$log_file"
    
    # Securely remove the temporary file
    shred -u "$temp_file" 2>/dev/null || rm -f "$temp_file"
    
    show_notification "Successfully randomized timestamps in $log_file" "success"
    log_action "Completed randomizing timestamps in $log_file"
    return 0
}

# Function to replace an IP address throughout all logs
replace_ip_address() {
    local old_ip="$1"
    local new_ip="$2"
    
    show_notification "Replacing IP address $old_ip with $new_ip in all logs..." "info"
    log_action "Started replacing IP address $old_ip with $new_ip in all logs"
    
    # Validate IP addresses
    if ! [[ "$old_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        show_notification "Error: Invalid source IP address format" "error"
        log_action "Error: Invalid source IP address format: $old_ip"
        return 1
    fi
    
    if ! [[ "$new_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        show_notification "Error: Invalid target IP address format" "error"
        log_action "Error: Invalid target IP address format: $new_ip"
        return 1
    fi
    
    # Find all log files containing the old IP
    local log_files=$(grep -l "$old_ip" /var/log/* 2>/dev/null)
    
    if [ -z "$log_files" ]; then
        show_notification "No logs found containing IP $old_ip" "warning"
        log_action "No logs found containing IP $old_ip"
        return 0
    fi
    
    # Process each log file
    local processed_count=0
    local total_files=$(echo "$log_files" | wc -l)
    
    for log_file in $log_files; do
        processed_count=$((processed_count + 1))
        show_progress $total_files $processed_count "Replacing IP in logs"
        
        # Create a temporary file
        local temp_file=$(mktemp)
        
        # Replace the IP address
        sed "s/$old_ip/$new_ip/g" "$log_file" > "$temp_file"
        
        # Replace the original file with the updated content
        cat "$temp_file" > "$log_file"
        
        # Securely remove the temporary file
        shred -u "$temp_file" 2>/dev/null || rm -f "$temp_file"
        
        log_action "Replaced IP $old_ip with $new_ip in $log_file"
    done
    
    show_notification "Successfully replaced IP $old_ip with $new_ip in $processed_count log files" "success"
    log_action "Completed replacing IP address $old_ip with $new_ip in all logs"
    return 0
}

# Function to remove a user's activity from all logs
remove_user_activity() {
    local username="$1"
    
    show_notification "Removing activity for user $username from all logs..." "info"
    log_action "Started removing activity for user $username from all logs"
    
    # Process auth logs
    if [ -f "/var/log/auth.log" ]; then
        sanitize_log_entries "$username" "/var/log/auth.log"
    fi
    
    # Process syslog
    if [ -f "/var/log/syslog" ]; then
        sanitize_log_entries "$username" "/var/log/syslog"
    fi
    
    # Process shell history files
    local user_home="/home/$username"
    if [ -d "$user_home" ]; then
        if [ -f "$user_home/.bash_history" ]; then
            secure_delete "$user_home/.bash_history"
            touch "$user_home/.bash_history"
            chown "$username:$username" "$user_home/.bash_history" 2>/dev/null
        fi
        
        if [ -f "$user_home/.zsh_history" ]; then
            secure_delete "$user_home/.zsh_history"
            touch "$user_home/.zsh_history"
            chown "$username:$username" "$user_home/.zsh_history" 2>/dev/null
        fi
        
        if [ -f "$user_home/.history" ]; then
            secure_delete "$user_home/.history"
            touch "$user_home/.history"
            chown "$username:$username" "$user_home/.history" 2>/dev/null
        fi
    fi
    
    # Process lastlog and wtmp
    if command_exists lastlog && command_exists utmpdump; then
        show_notification "Removing user $username from lastlog and wtmp..." "info"
        
        # Handle wtmp file
        if [ -f "/var/log/wtmp" ]; then
            local temp_file=$(mktemp)
            utmpdump /var/log/wtmp | grep -v "$username" > "$temp_file"
            cat "$temp_file" | utmpdump -r > /var/log/wtmp
            shred -u "$temp_file" 2>/dev/null || rm -f "$temp_file"
            log_action "Removed $username from wtmp"
        fi
        
        # Handle lastlog file
        if [ -f "/var/log/lastlog" ]; then
            # Get user ID
            local uid=$(id -u "$username" 2>/dev/null)
            if [ -n "$uid" ]; then
                # Create a binary zero record of appropriate size
                dd if=/dev/zero of="/var/log/lastlog" bs=1 count=292 seek=$((uid * 292)) conv=notrunc 2>/dev/null
                log_action "Cleared $username from lastlog"
                show_notification "Cleared user from lastlog" "success"
            else
                show_notification "Could not find UID for $username" "warning"
                log_action "Could not find UID for $username to clear lastlog"
            fi
        fi
    fi
    
    show_notification "Activity removal for user $username completed" "success"
    log_action "Completed removing activity for user $username from all logs"
    return 0
}

# Function to handle advanced anti-forensics operations
handle_anti_forensics() {
    clear
    display_section_header "Advanced Anti-Forensics Operations"
    
    local options=(
        "Sanitize Specific Log Entries (by pattern)"
        "Manipulate File Timestamps"
        "Securely Delete Files"
        "Hide Events Within Time Range"
        "Edit Log Entries (search and replace)"
        "Randomize Timestamps in Log Files"
        "Replace IP Address in All Logs"
        "Remove User Activity from All Logs"
        "Return to Main Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" choice

    case $choice in
        1)
            read -p "$(echo -e "${YELLOW}Enter pattern to remove:${NC} ")" pattern
            read -p "$(echo -e "${YELLOW}Enter log file path:${NC} ")" log_file
            sanitize_log_entries "$pattern" "$log_file"
            sleep 2
            handle_anti_forensics
            ;;
        2)
            read -p "$(echo -e "${YELLOW}Enter file path:${NC} ")" file
            read -p "$(echo -e "${YELLOW}Use reference file? (y/n):${NC} ")" use_ref
            
            if [[ "$use_ref" =~ ^[Yy]$ ]]; then
                read -p "$(echo -e "${YELLOW}Enter reference file path:${NC} ")" ref_file
                manipulate_timestamp "$file" "$ref_file"
            else
                manipulate_timestamp "$file" ""
            fi
            sleep 2
            handle_anti_forensics
            ;;
        3)
            read -p "$(echo -e "${YELLOW}Enter file path:${NC} ")" file
            read -p "$(echo -e "${YELLOW}Enter number of passes [3]:${NC} ")" passes
            passes=${passes:-3}
            secure_delete "$file" "$passes"
            sleep 2
            handle_anti_forensics
            ;;
        4)
            read -p "$(echo -e "${YELLOW}Enter log file path:${NC} ")" log_file
            read -p "$(echo -e "${YELLOW}Enter start time (format: 'YYYY-MM-DD HH:MM:SS'):${NC} ")" start_time
            read -p "$(echo -e "${YELLOW}Enter end time (format: 'YYYY-MM-DD HH:MM:SS'):${NC} ")" end_time
            hide_time_range "$log_file" "$start_time" "$end_time"
            sleep 2
            handle_anti_forensics
            ;;
        5)
            read -p "$(echo -e "${YELLOW}Enter log file path:${NC} ")" log_file
            read -p "$(echo -e "${YELLOW}Enter search pattern:${NC} ")" search
            read -p "$(echo -e "${YELLOW}Enter replacement:${NC} ")" replace
            edit_log_entries "$log_file" "$search" "$replace"
            sleep 2
            handle_anti_forensics
            ;;
        6)
            read -p "$(echo -e "${YELLOW}Enter log file path:${NC} ")" log_file
            read -p "$(echo -e "${YELLOW}Enter time variance in seconds [3600]:${NC} ")" variance
            variance=${variance:-3600}
            randomize_timestamps "$log_file" "$variance"
            sleep 2
            handle_anti_forensics
            ;;
        7)
            read -p "$(echo -e "${YELLOW}Enter IP address to replace:${NC} ")" old_ip
            read -p "$(echo -e "${YELLOW}Enter new IP address:${NC} ")" new_ip
            replace_ip_address "$old_ip" "$new_ip"
            sleep 2
            handle_anti_forensics
            ;;
        8)
            read -p "$(echo -e "${YELLOW}Enter username:${NC} ")" username
            remove_user_activity "$username"
            sleep 2
            handle_anti_forensics
            ;;
        9)
            return 0
            ;;
        *)
            show_notification "Invalid option" "error"
            sleep 1
            handle_anti_forensics
            ;;
    esac
} 