#!/bin/bash

# Advanced log cleaner module for LogWipe

# Global variables
verbose=false

clean_logs() {
    local mode="${1:-all}"
    show_notification "Starting advanced log cleaning process..." "info"
    log_action "Started log cleaning with mode: $mode"
    
    case "$mode" in
        "all")
            clean_system_logs
            clean_user_logs
            clean_application_logs
            clean_network_traces
            clean_system_traces
            ;;
        "system")
            clean_system_logs
            clean_system_traces
            ;;
        "user")
            clean_user_logs
            ;;
        "application")
            clean_application_logs
            ;;
        "network")
            clean_network_traces
            ;;
        *)
            show_notification "Unknown cleaning mode: $mode" "error"
            log_action "Error: Unknown cleaning mode: $mode"
            return 1
            ;;
    esac

    show_notification "Advanced log cleaning completed!" "success"
    log_action "Completed log cleaning with mode: $mode"
    sleep 2
}

# System logs
clean_system_logs() {
    show_notification "Cleaning system logs..." "info"
    log_action "Started cleaning system logs"
    
    # Create a list of system log files
    local system_logs=(
        "/var/log/syslog"
        "/var/log/messages"
        "/var/log/auth.log"
        "/var/log/kern.log"
        "/var/log/dmesg"
        "/var/log/btmp"
        "/var/log/wtmp"
        "/var/log/lastlog"
        "/var/log/faillog"
        "/var/log/daemon.log"
        "/var/log/debug"
        "/var/log/mail.log"
        "/var/log/user.log"
    )
    
    # Total number of logs to clean
    local total_logs=${#system_logs[@]}
    local cleaned_logs=0
    
    # Clean each log file if it exists
    for log_file in "${system_logs[@]}"; do
        cleaned_logs=$((cleaned_logs + 1))
        show_progress $total_logs $cleaned_logs "Cleaning system logs"
        
        if [ -f "$log_file" ]; then
            if [ "$verbose" = true ]; then
                show_notification "Cleaning $log_file" "info"
            fi
            > "$log_file" 2>/dev/null && log_action "Cleaned $log_file" || log_action "Failed to clean $log_file"
        fi
        sleep 0.1
    done
    
    # Clear journal logs if journalctl exists
    if command_exists journalctl; then
        show_notification "Clearing journal logs..." "info"
        journalctl --flush 2>/dev/null
        journalctl --rotate 2>/dev/null
        journalctl --vacuum-time=1s 2>/dev/null
        log_action "Cleared journal logs"
    fi
    
    # Clear systemd logs if systemd is installed
    if command_exists systemctl; then
        show_notification "Clearing systemd logs..." "info"
        systemctl stop systemd-journald 2>/dev/null
        rm -rf /var/log/journal/* 2>/dev/null
        systemctl start systemd-journald 2>/dev/null
        log_action "Cleared systemd logs"
    fi
    
    # Clear audit logs if they exist
    if [ -f "/var/log/audit/audit.log" ]; then
        show_notification "Clearing audit logs..." "info"
        > /var/log/audit/audit.log 2>/dev/null
        if command_exists auditctl; then
            auditctl -D 2>/dev/null
        fi
        log_action "Cleared audit logs"
    fi
    
    # Clear kernel ring buffer if dmesg exists
    if command_exists dmesg; then
        show_notification "Clearing kernel ring buffer..." "info"
        dmesg -C 2>/dev/null
        log_action "Cleared kernel ring buffer"
    fi
    
    show_notification "System logs cleaned!" "success"
}

# User logs and traces
clean_user_logs() {
    show_notification "Cleaning user logs and traces..." "info"
    log_action "Started cleaning user logs"
    
    # Get list of user home directories
    local user_homes=("/root" "/home/"*)
    
    # History files to clean
    local history_files=(
        ".bash_history"
        ".zsh_history"
        ".fish_history"
        ".history"
        ".sh_history"
        ".mysql_history"
        ".psql_history"
        ".python_history"
        ".node_repl_history"
        ".lesshst"
        ".viminfo"
    )
    
    # Total number of users to process
    local total_users=${#user_homes[@]}
    local processed_users=0
    
    # Clear shell histories for all users
    for user_home in "${user_homes[@]}"; do
        processed_users=$((processed_users + 1))
        show_progress $total_users $processed_users "Cleaning user logs"
        
        if [ -d "$user_home" ]; then
            local username=$(basename "$user_home")
            
            if [ "$verbose" = true ]; then
                show_notification "Processing user: $username" "info"
            fi
            
            for history_file in "${history_files[@]}"; do
                local full_path="$user_home/$history_file"
                if [ -f "$full_path" ]; then
                    if [ "$verbose" = true ]; then
                        show_notification "Cleaning $full_path" "info"
                    fi
                    > "$full_path" 2>/dev/null && log_action "Cleaned $full_path" || log_action "Failed to clean $full_path"
                fi
            done
            
            # Clean specific user cache and temporary files
            if [ -d "$user_home/.cache" ]; then
                rm -rf "$user_home/.cache/"* 2>/dev/null
                log_action "Cleared cache files for $username"
            fi
            
            if [ -d "$user_home/.local/share/Trash" ]; then
                rm -rf "$user_home/.local/share/Trash/"* 2>/dev/null
                log_action "Cleared trash for $username"
            fi
            
            # Clear browser data
            rm -rf "$user_home/.mozilla/firefox/"*/Cache/* 2>/dev/null
            rm -rf "$user_home/.config/google-chrome/Default/Cache/"* 2>/dev/null
            rm -rf "$user_home/.config/chromium/Default/Cache/"* 2>/dev/null
            log_action "Cleared browser caches for $username"
            
            # Clear recent files
            rm -f "$user_home/.local/share/recently-used.xbel" 2>/dev/null
            rm -f "$user_home/.local/share/RecentDocuments/"* 2>/dev/null
            log_action "Cleared recent files for $username"
            
            # Clear thumbnails
            rm -rf "$user_home/.thumbnails/"* 2>/dev/null
            rm -rf "$user_home/.cache/thumbnails/"* 2>/dev/null
            log_action "Cleared thumbnails for $username"
        fi
        
        sleep 0.1
    done
    
    # Clear current history
    history -c 2>/dev/null
    
    # Clear temporary directories
    show_notification "Clearing temporary directories..." "info"
    rm -rf /tmp/* 2>/dev/null
    rm -rf /var/tmp/* 2>/dev/null
    log_action "Cleared temporary directories"
    
    show_notification "User logs and traces cleaned!" "success"
}

# Application logs and traces
clean_application_logs() {
    show_notification "Cleaning application logs and traces..." "info"
    log_action "Started cleaning application logs"
    
    # Web server logs
    local web_logs=(
        "/var/log/apache2/access.log"
        "/var/log/apache2/error.log"
        "/var/log/httpd/access_log"
        "/var/log/httpd/error_log"
        "/var/log/nginx/access.log"
        "/var/log/nginx/error.log"
    )
    
    # Database logs
    local db_logs=(
        "/var/log/mysql/error.log"
        "/var/log/mysql.log"
        "/var/log/postgresql/postgresql-*.log"
        "/var/log/mongodb/mongodb.log"
    )
    
    # Package manager logs
    local pkg_logs=(
        "/var/log/dpkg.log"
        "/var/log/apt/history.log"
        "/var/log/apt/term.log"
        "/var/log/yum.log"
        "/var/log/dnf.log"
    )
    
    # Cron and mail logs
    local other_logs=(
        "/var/log/cron.log"
        "/var/log/mail.log"
        "/var/log/mail.err"
        "/var/log/maillog"
    )
    
    # Total number of log types
    local total_steps=4
    local current_step=0
    
    # Clean each category of logs
    current_step=$((current_step + 1))
    show_progress $total_steps $current_step "Cleaning web server logs"
    clean_log_files "${web_logs[@]}"
    sleep 0.5
    
    current_step=$((current_step + 1))
    show_progress $total_steps $current_step "Cleaning database logs"
    clean_log_files "${db_logs[@]}"
    sleep 0.5
    
    current_step=$((current_step + 1))
    show_progress $total_steps $current_step "Cleaning package manager logs"
    clean_log_files "${pkg_logs[@]}"
    sleep 0.5
    
    current_step=$((current_step + 1))
    show_progress $total_steps $current_step "Cleaning system service logs"
    clean_log_files "${other_logs[@]}"
    sleep 0.5
    
    # Clean all logs in /var/log that are files (not directories)
    show_notification "Cleaning all remaining log files in /var/log..." "info"
    find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null
    find /var/log -type f -name "*.log.*" -exec truncate -s 0 {} \; 2>/dev/null
    log_action "Cleaned all log files in /var/log"
    
    show_notification "Application logs and traces cleaned!" "success"
}

# Network traces
clean_network_traces() {
    show_notification "Cleaning network traces..." "info"
    log_action "Started cleaning network traces"
    
    # Total steps for network trace cleaning
    local total_steps=4
    local current_step=0
    
    # Clear ARP cache if ip command exists
    if command_exists ip; then
        current_step=$((current_step + 1))
        show_progress $total_steps $current_step "Clearing ARP cache"
        ip -s -s neigh flush all 2>/dev/null
        log_action "Cleared ARP cache"
        sleep 0.5
    fi
    
    # Clear routing cache if ip command exists
    if command_exists ip; then
        current_step=$((current_step + 1))
        show_progress $total_steps $current_step "Clearing routing cache"
        ip route flush cache 2>/dev/null
        log_action "Cleared routing cache"
        sleep 0.5
    fi
    
    # Clear connection tracking if conntrack exists
    if command_exists conntrack; then
        current_step=$((current_step + 1))
        show_progress $total_steps $current_step "Clearing connection tracking"
        conntrack -F 2>/dev/null
        log_action "Cleared connection tracking"
        sleep 0.5
    fi
    
    # Clear DNS cache based on the system
    current_step=$((current_step + 1))
    show_progress $total_steps $current_step "Clearing DNS cache"
    if command_exists systemd-resolve; then
        systemd-resolve --flush-caches 2>/dev/null
        log_action "Cleared DNS cache using systemd-resolve"
    elif command_exists resolvectl; then
        resolvectl flush-caches 2>/dev/null
        log_action "Cleared DNS cache using resolvectl"
    elif [ -f "/etc/init.d/nscd" ]; then
        /etc/init.d/nscd restart 2>/dev/null
        log_action "Cleared DNS cache by restarting NSCD"
    fi
    sleep 0.5
    
    # Clear SSH known hosts for all users
    show_notification "Clearing SSH known hosts..." "info"
    local user_homes=("/root" "/home/"*)
    for user_home in "${user_homes[@]}"; do
        if [ -f "$user_home/.ssh/known_hosts" ]; then
            > "$user_home/.ssh/known_hosts" 2>/dev/null
            log_action "Cleared SSH known hosts for $(basename "$user_home")"
        fi
    done
    
    show_notification "Network traces cleaned!" "success"
}

# System traces
clean_system_traces() {
    show_notification "Cleaning system traces..." "info"
    log_action "Started cleaning system traces"
    
    # Total steps for system trace cleaning
    local total_steps=4
    local current_step=0
    
    # Clear swap if it exists
    if [ -n "$(swapon --show)" ]; then
        current_step=$((current_step + 1))
        show_progress $total_steps $current_step "Clearing swap"
        swapoff -a 2>/dev/null && swapon -a 2>/dev/null
        log_action "Cleared swap"
        sleep 0.5
    else
        current_step=$((current_step + 1))
        show_progress $total_steps $current_step "No swap to clear"
        sleep 0.5
    fi
    
    # Clear memory cache
    if [ -f "/proc/sys/vm/drop_caches" ]; then
        current_step=$((current_step + 1))
        show_progress $total_steps $current_step "Clearing memory cache"
        sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        log_action "Cleared memory cache"
        sleep 0.5
    else
        current_step=$((current_step + 1))
        show_progress $total_steps $current_step "No memory cache to clear"
        sleep 0.5
    fi
    
    # Clear systemd journal if journalctl exists
    if command_exists journalctl; then
        current_step=$((current_step + 1))
        show_progress $total_steps $current_step "Clearing systemd journal"
        journalctl --vacuum-time=1s 2>/dev/null
        journalctl --vacuum-size=1M 2>/dev/null
        log_action "Cleared systemd journal"
        sleep 0.5
    else
        current_step=$((current_step + 1))
        show_progress $total_steps $current_step "No systemd journal to clear"
        sleep 0.5
    fi
    
    # Clear package cache based on the package manager
    current_step=$((current_step + 1))
    show_progress $total_steps $current_step "Clearing package cache"
    if command_exists apt-get; then
        apt-get clean 2>/dev/null
        log_action "Cleared APT package cache"
    elif command_exists yum; then
        yum clean all 2>/dev/null
        log_action "Cleared YUM package cache"
    elif command_exists dnf; then
        dnf clean all 2>/dev/null
        log_action "Cleared DNF package cache"
    else
        log_action "No package manager cache to clear"
    fi
    sleep 0.5
    
    show_notification "System traces cleaned!" "success"
}

# Custom log cleaning function
custom_log_cleaning() {
    clear
    display_section_header "Custom Log Cleaning"
    
    local options=(
        "System logs (/var/log/syslog, etc.)"
        "Authentication logs"
        "Kernel logs"
        "Bash/Shell histories"
        "Web server logs (Apache, Nginx)"
        "Database logs (MySQL, PostgreSQL)"
        "Package manager logs"
        "Mail logs"
        "Browser data"
        "Temporary files"
        "Network caches"
        "Memory and swap"
        "Return to Previous Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    echo -e "${YELLOW}Enter your selections (e.g., 1,3,5) or 13 to return:${NC}"
    read selections
    
    if [ "$selections" = "13" ]; then
        return
    fi
    
    # Parse the selections
    IFS=',' read -ra selected_options <<< "$selections"
    
    # Perform the selected cleaning operations
    for option in "${selected_options[@]}"; do
        case "$option" in
            1) 
                show_notification "Cleaning system logs..." "info"
                clean_specific_logs "/var/log/syslog" "/var/log/messages" 
                ;;
            2) 
                show_notification "Cleaning authentication logs..." "info"
                clean_specific_logs "/var/log/auth.log" "/var/log/secure" 
                ;;
            3) 
                show_notification "Cleaning kernel logs..." "info"
                clean_specific_logs "/var/log/kern.log" "/var/log/dmesg" 
                ;;
            4) 
                show_notification "Cleaning user histories..." "info"
                clean_user_histories 
                ;;
            5) 
                show_notification "Cleaning web server logs..." "info"
                clean_specific_logs "/var/log/apache2/*" "/var/log/httpd/*" "/var/log/nginx/*" 
                ;;
            6) 
                show_notification "Cleaning database logs..." "info"
                clean_specific_logs "/var/log/mysql/*" "/var/log/postgresql/*" 
                ;;
            7) 
                show_notification "Cleaning package manager logs..." "info"
                clean_specific_logs "/var/log/dpkg.log" "/var/log/apt/*" "/var/log/yum.log" 
                ;;
            8) 
                show_notification "Cleaning mail logs..." "info"
                clean_specific_logs "/var/log/mail.log" "/var/log/maillog" 
                ;;
            9) 
                show_notification "Cleaning browser data..." "info"
                clean_browser_data 
                ;;
            10) 
                show_notification "Cleaning temporary files..." "info"
                rm -rf /tmp/* /var/tmp/* 2>/dev/null 
                ;;
            11) 
                show_notification "Cleaning network traces..." "info"
                clean_network_traces 
                ;;
            12) 
                show_notification "Cleaning memory and swap..." "info"
                clean_memory_swap 
                ;;
            *) show_notification "Invalid option: $option" "error" ;;
        esac
    done
    
    show_notification "Custom cleaning completed!" "success"
    sleep 2
}

# Helper function to clean specific log files
clean_specific_logs() {
    for log_pattern in "$@"; do
        for log_file in $log_pattern; do
            if [ -f "$log_file" ]; then
                if [ "$verbose" = true ]; then
                    show_notification "Cleaning $log_file" "info"
                fi
                > "$log_file" 2>/dev/null && log_action "Cleaned $log_file" || log_action "Failed to clean $log_file"
            fi
        done
    done
}

# Helper function to clean a list of log files
clean_log_files() {
    for log_file in "$@"; do
        if [ -f "$log_file" ]; then
            if [ "$verbose" = true ]; then
                show_notification "Cleaning $log_file" "info"
            fi
            > "$log_file" 2>/dev/null && log_action "Cleaned $log_file" || log_action "Failed to clean $log_file"
        fi
    done
}

# Helper function to clean user histories
clean_user_histories() {
    local user_homes=("/root" "/home/"*)
    local history_files=(
        ".bash_history"
        ".zsh_history"
        ".fish_history"
        ".history"
        ".sh_history"
    )
    
    for user_home in "${user_homes[@]}"; do
        if [ -d "$user_home" ]; then
            for history_file in "${history_files[@]}"; do
                local full_path="$user_home/$history_file"
                if [ -f "$full_path" ]; then
                    > "$full_path" 2>/dev/null
                    log_action "Cleaned $full_path"
                fi
            done
        fi
    done
    
    history -c 2>/dev/null
}

# Helper function to clean browser data
clean_browser_data() {
    local user_homes=("/root" "/home/"*)
    
    for user_home in "${user_homes[@]}"; do
        if [ -d "$user_home" ]; then
            rm -rf "$user_home/.mozilla/firefox/"*/Cache/* 2>/dev/null
            rm -rf "$user_home/.config/google-chrome/Default/Cache/"* 2>/dev/null
            rm -rf "$user_home/.config/chromium/Default/Cache/"* 2>/dev/null
            log_action "Cleared browser caches for $(basename "$user_home")"
        fi
    done
}

# Helper function to clean memory and swap
clean_memory_swap() {
    if [ -n "$(swapon --show 2>/dev/null)" ]; then
        swapoff -a 2>/dev/null && swapon -a 2>/dev/null
        log_action "Cleared swap"
        show_notification "Swap cleared" "success"
    else
        show_notification "No swap to clear" "warning"
    fi
    
    if [ -f "/proc/sys/vm/drop_caches" ]; then
        sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        log_action "Cleared memory cache"
        show_notification "Memory cache cleared" "success"
    else
        show_notification "Unable to clear memory cache" "warning"
    fi
} 