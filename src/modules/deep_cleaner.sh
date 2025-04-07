#!/bin/bash

# Deep Cleaner Module for LogWipe - Advanced Trace Elimination
# This module provides cutting-edge techniques to eliminate traces
# beyond what standard log cleaning and anti-forensics can achieve

# Function to clean memory artifacts
clean_memory_artifacts() {
    show_notification "Cleaning memory artifacts..." "info"
    log_action "Started cleaning memory artifacts"
    
    # Drop caches
    if confirm_action "Drop system caches?" "Y"; then
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        sync
        log_action "Dropped system caches"
        show_notification "System caches dropped" "success"
    fi
    
    # Clear swap space
    if [ -n "$(swapon --show 2>/dev/null)" ]; then
        if confirm_action "Clear swap space? (This will temporarily disable swap)" "Y"; then
            swapoff -a
            swapon -a
            log_action "Cleared swap space"
            show_notification "Swap space cleared" "success"
        fi
    fi
    
    # Clear shared memory segments
    if command_exists ipcrm; then
        for shm in $(ipcs -m | grep $(whoami) | awk '{print $2}'); do
            ipcrm -m "$shm" 2>/dev/null
        done
        log_action "Cleared shared memory segments"
        show_notification "Shared memory segments cleared" "success"
    fi
    
    # Overwrite free RAM with zeros using a custom approach
    if confirm_action "Attempt to overwrite free RAM? (May cause system slowdown)" "N"; then
        show_notification "Overwriting free RAM with zeros..." "info"
        
        # Calculate available memory
        mem_available=$(grep MemAvailable /proc/meminfo | awk '{print int($2 * 0.8)}')
        
        # Use dd to create a large file filled with zeros to consume memory
        (dd if=/dev/zero of=/dev/null bs=1M count=$mem_available status=none & 
         pid=$!
         sleep 5
         kill -9 $pid) 2>/dev/null
        
        log_action "Attempted to overwrite free RAM"
        show_notification "Free RAM overwrite attempted" "success"
    fi
    
    return 0
}

# Function to clean process history
clean_process_history() {
    show_notification "Cleaning process history..." "info"
    log_action "Started cleaning process history"
    
    # Clean .bash_history equivalents for all users
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            username=$(basename "$user_home")
            
            # All known shell history files
            for hist_file in ".bash_history" ".zsh_history" ".sh_history" ".history" ".ksh_history" \
                             ".fish_history" ".lesshst" ".python_history" ".node_repl_history" \
                             ".sqlite_history" ".mysql_history" ".psql_history"; do
                if [ -f "$user_home/$hist_file" ]; then
                    show_notification "Cleaning $hist_file for user $username..." "info"
                    cat /dev/null > "$user_home/$hist_file" 2>/dev/null
                    log_action "Cleaned $hist_file for user $username"
                fi
            done
        fi
    done
    
    # Also clean root's history files
    for hist_file in "/root/.bash_history" "/root/.zsh_history" "/root/.sh_history" "/root/.history"; do
        if [ -f "$hist_file" ]; then
            cat /dev/null > "$hist_file" 2>/dev/null
            log_action "Cleaned $hist_file for root"
        fi
    done
    
    # Clean command-not-found history
    if [ -d "/var/lib/command-not-found" ]; then
        rm -f /var/lib/command-not-found/*.sqlite 2>/dev/null
        log_action "Removed command-not-found history"
    fi
    
    # Clean systemd journal volatile logs
    if command_exists journalctl; then
        journalctl --rotate 2>/dev/null
        journalctl --vacuum-time=1s 2>/dev/null
        log_action "Cleared systemd journal logs"
        show_notification "Systemd journal logs cleared" "success"
    fi
    
    # Clean kernel ring buffer
    if command_exists dmesg; then
        dmesg -c > /dev/null 2>&1
        log_action "Cleared kernel ring buffer"
        show_notification "Kernel ring buffer cleared" "success"
    fi
    
    return 0
}

# Function to clean temporary files and caches
clean_temps_and_caches() {
    show_notification "Cleaning temporary files and caches..." "info"
    log_action "Started cleaning temporary files and caches"
    
    # Clean /tmp
    find /tmp -type f -exec rm -f {} \; 2>/dev/null
    log_action "Cleaned /tmp directory"
    
    # Clean /var/tmp
    find /var/tmp -type f -exec rm -f {} \; 2>/dev/null
    log_action "Cleaned /var/tmp directory"
    
    # Clean user caches
    for user_home in /home/*; do
        if [ -d "$user_home/.cache" ]; then
            rm -rf "$user_home/.cache"/* 2>/dev/null
            log_action "Cleaned cache for user $(basename "$user_home")"
        fi
    done
    
    # Clean apt/yum/dnf cache if present
    if [ -d "/var/cache/apt" ]; then
        apt-get clean 2>/dev/null
        log_action "Cleaned apt cache"
    fi
    
    if [ -d "/var/cache/yum" ]; then
        yum clean all 2>/dev/null
        log_action "Cleaned yum cache"
    fi
    
    if [ -d "/var/cache/dnf" ]; then
        dnf clean all 2>/dev/null
        log_action "Cleaned dnf cache"
    fi
    
    # Clean thumbnails
    find /home -path "*/thumbnails/*" -type f -exec rm -f {} \; 2>/dev/null
    log_action "Cleaned thumbnail caches"
    
    show_notification "Temporary files and caches cleaned" "success"
    return 0
}

# Function to clean filesystem and disk traces
clean_filesystem_traces() {
    show_notification "Cleaning filesystem traces..." "info"
    log_action "Started cleaning filesystem traces"
    
    # Clean file access times
    if confirm_action "Reset access times for recently accessed files?" "Y"; then
        show_notification "Resetting access times for recently accessed files..." "info"
        
        # Find recently accessed files (within last 24 hours)
        local recent_files=$(find /home -type f -atime -1 2>/dev/null | grep -v "^\." | head -1000)
        
        # Get a reference timestamp (7 days ago)
        local ref_timestamp=$(date -d "7 days ago" +"%Y%m%d%H%M.%S")
        
        # Reset access times
        for file in $recent_files; do
            touch -a -t "$ref_timestamp" "$file" 2>/dev/null
        done
        
        log_action "Reset access times for recently accessed files"
        show_notification "Access times reset" "success"
    fi
    
    # Clean extended attributes that may contain metadata
    if command_exists setfattr; then
        show_notification "Cleaning extended file attributes..." "info"
        
        # Find files with extended attributes
        local files_with_xattr=$(find /home -type f -exec bash -c 'getfattr -d "{}" 2>/dev/null | grep -q "^attribute" && echo "{}"' \; 2>/dev/null)
        
        for file in $files_with_xattr; do
            # List all attributes and remove them
            for attr in $(getfattr -d "$file" 2>/dev/null | grep "=" | cut -d= -f1); do
                setfattr -x "$attr" "$file" 2>/dev/null
            done
        done
        
        log_action "Cleaned extended file attributes"
        show_notification "Extended file attributes cleaned" "success"
    fi
    
    # Clean journal inodes on ext4 filesystems
    if command_exists tune2fs; then
        if confirm_action "Clean filesystem journals? (May require remount)" "N"; then
            show_notification "Cleaning filesystem journals..." "info"
            
            # Find ext4 partitions
            local ext4_partitions=$(mount | grep " type ext4" | cut -d' ' -f1)
            
            for partition in $ext4_partitions; do
                # This is potentially dangerous, so add extra confirmation
                if confirm_action "Clean journal for $partition? This is potentially risky" "N"; then
                    # Try to disable journaling temporarily
                    mount -o remount,noload "$partition" 2>/dev/null
                    tune2fs -O ^has_journal "$partition" 2>/dev/null
                    tune2fs -O has_journal "$partition" 2>/dev/null
                    mount -o remount "$partition" 2>/dev/null
                    log_action "Cleaned journal for $partition"
                fi
            done
            
            show_notification "Filesystem journals cleaned" "success"
        fi
    fi
    
    # Clean disk slack space if user confirms
    if confirm_action "Overwrite free disk space to eliminate file remnants? (This may take a long time)" "N"; then
        clean_disk_slack_space
    fi
    
    return 0
}

# Function to wipe disk slack space
clean_disk_slack_space() {
    show_notification "Overwriting free disk space..." "info"
    log_action "Started overwriting free disk space"
    
    # Determine mount points to clean
    local mount_points=("/home" "/var" "/tmp")
    
    for mount_point in "${mount_points[@]}"; do
        show_notification "Processing $mount_point..." "info"
        
        # Create a temporary file and fill it with zeros until disk is full
        local temp_file="$mount_point/logwipe_freespace_$$"
        
        # Try to fill the disk with zeros, but stop if we get an error
        dd if=/dev/zero of="$temp_file" bs=1M conv=notrunc &>/dev/null || true
        
        # Remove the temporary file
        rm -f "$temp_file"
        
        log_action "Overwritten free space on $mount_point"
        show_notification "Free space on $mount_point overwritten" "success"
    done
    
    return 0
}

# Function to clean network traces
clean_network_traces() {
    show_notification "Cleaning network traces..." "info"
    log_action "Started cleaning network traces"
    
    # Clean arp cache
    if command_exists ip; then
        ip -s -s neigh flush all &>/dev/null
        log_action "Cleared ARP cache"
        show_notification "ARP cache cleared" "success"
    elif command_exists arp; then
        arp -d -a &>/dev/null
        log_action "Attempted to clear ARP cache"
    fi
    
    # Clean DNS cache
    if command_exists systemd-resolve; then
        systemd-resolve --flush-caches &>/dev/null
        log_action "Cleared systemd DNS cache"
        show_notification "DNS cache cleared" "success"
    elif [ -f /etc/init.d/nscd ]; then
        /etc/init.d/nscd restart &>/dev/null
        log_action "Restarted NSCD to clear DNS cache"
    fi
    
    # Clean netstat data
    if [ -d "/proc/net" ]; then
        if confirm_action "Clean network connection states? (May disrupt active connections)" "N"; then
            echo 1 > /proc/sys/net/ipv4/tcp_timestamps 2>/dev/null
            echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle 2>/dev/null
            log_action "Adjusted network parameters to flush connection states"
            show_notification "Network connection states cleaned" "success"
        fi
    fi
    
    # Clean SSH known hosts and connection history
    for user_home in /home/*; do
        if [ -d "$user_home/.ssh" ]; then
            username=$(basename "$user_home")
            
            # Remove known_hosts
            if [ -f "$user_home/.ssh/known_hosts" ]; then
                cat /dev/null > "$user_home/.ssh/known_hosts" 2>/dev/null
                log_action "Cleaned SSH known hosts for user $username"
            fi
            
            # Clean SSH connection history
            if [ -d "$user_home/.ssh/connection_history" ]; then
                rm -rf "$user_home/.ssh/connection_history" 2>/dev/null
                log_action "Cleaned SSH connection history for user $username"
            fi
        fi
    done
    
    # Also clean root's SSH history
    if [ -f "/root/.ssh/known_hosts" ]; then
        cat /dev/null > "/root/.ssh/known_hosts" 2>/dev/null
        log_action "Cleaned SSH known hosts for root"
    fi
    
    # Clean routing cache
    if command_exists ip; then
        ip route flush cache &>/dev/null
        log_action "Flushed routing cache"
        show_notification "Routing cache flushed" "success"
    fi
    
    return 0
}

# Function to clean application-specific traces
clean_application_traces() {
    show_notification "Cleaning application-specific traces..." "info"
    log_action "Started cleaning application-specific traces"
    
    # Clean browser histories for all users
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            username=$(basename "$user_home")
            
            # Firefox
            find "$user_home/.mozilla/firefox" -name "places.sqlite" -exec sqlite3 {} "DELETE FROM moz_historyvisits; DELETE FROM moz_places;" \; 2>/dev/null
            find "$user_home/.mozilla/firefox" -name "cookies.sqlite" -exec sqlite3 {} "DELETE FROM moz_cookies;" \; 2>/dev/null
            
            # Chrome/Chromium
            find "$user_home/.config/google-chrome" -name "History" -exec sqlite3 {} "DELETE FROM visits; DELETE FROM urls;" \; 2>/dev/null
            find "$user_home/.config/chromium" -name "History" -exec sqlite3 {} "DELETE FROM visits; DELETE FROM urls;" \; 2>/dev/null
            
            # Clear browser caches
            rm -rf "$user_home/.cache/mozilla"/* 2>/dev/null
            rm -rf "$user_home/.cache/google-chrome"/* 2>/dev/null
            rm -rf "$user_home/.cache/chromium"/* 2>/dev/null
            
            log_action "Cleaned browser histories for user $username"
        fi
    done
    
    # Clean vim/nano/emacs editor traces
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            username=$(basename "$user_home")
            
            # Clean vim info
            find "$user_home" -name ".viminfo" -exec cat /dev/null > {} \; 2>/dev/null
            
            # Clean nano history
            find "$user_home" -name ".nano_history" -exec cat /dev/null > {} \; 2>/dev/null
            
            # Clean emacs history
            find "$user_home" -name ".emacs.d/history" -exec cat /dev/null > {} \; 2>/dev/null
            
            log_action "Cleaned editor histories for user $username"
        fi
    done
    
    # Clean systemwide editor traces
    if [ -f "/root/.viminfo" ]; then
        cat /dev/null > "/root/.viminfo" 2>/dev/null
        log_action "Cleaned vim history for root"
    fi
    
    # Remove application crash reports and core dumps
    rm -rf /var/crash/* 2>/dev/null
    rm -f /core 2>/dev/null
    find / -name "core" -type f -delete 2>/dev/null
    
    # Clean recent documents lists
    for user_home in /home/*; do
        if [ -d "$user_home/.local/share/recently-used.xbel" ]; then
            cat /dev/null > "$user_home/.local/share/recently-used.xbel" 2>/dev/null
            log_action "Cleaned recent documents for user $(basename "$user_home")"
        fi
    done
    
    show_notification "Application-specific traces cleaned" "success"
    return 0
}

# Function to clean audit logs and monitoring services
clean_audit_traces() {
    show_notification "Cleaning audit logs and monitoring traces..." "info"
    log_action "Started cleaning audit logs and monitoring traces"
    
    # Clean Linux audit logs
    if command_exists auditctl; then
        if confirm_action "Clear audit logs? This might alert security monitoring systems" "N"; then
            auditctl -e 0 2>/dev/null  # Temporarily disable auditing
            cat /dev/null > /var/log/audit/audit.log 2>/dev/null
            auditctl -e 1 2>/dev/null  # Re-enable auditing
            log_action "Cleared audit logs"
            show_notification "Audit logs cleared" "success"
        fi
    fi
    
    # Restart the auditd service to clear in-memory state
    if command_exists service; then
        if confirm_action "Restart audit daemon? This might alert security monitoring systems" "N"; then
            service auditd restart &>/dev/null
            log_action "Restarted audit daemon"
            show_notification "Audit daemon restarted" "success"
        fi
    fi
    
    # Clean utmp, wtmp, btmp (login records)
    if confirm_action "Clean login records (utmp/wtmp/btmp)?" "Y"; then
        cat /dev/null > /var/run/utmp 2>/dev/null
        cat /dev/null > /var/log/wtmp 2>/dev/null
        cat /dev/null > /var/log/btmp 2>/dev/null
        log_action "Cleared utmp/wtmp/btmp records"
        show_notification "Login records cleared" "success"
    fi
    
    # Clean lastlog
    if [ -f "/var/log/lastlog" ]; then
        if confirm_action "Clean lastlog?" "Y"; then
            cat /dev/null > /var/log/lastlog 2>/dev/null
            log_action "Cleared lastlog"
            show_notification "Last login records cleared" "success"
        fi
    fi
    
    # Check for and clean OSSEC logs if present
    if [ -d "/var/ossec" ]; then
        cat /dev/null > /var/ossec/logs/alerts/alerts.log 2>/dev/null
        cat /dev/null > /var/ossec/logs/ossec.log 2>/dev/null
        log_action "Cleared OSSEC logs"
    fi
    
    # Check for and clean Wazuh logs if present
    if [ -d "/var/ossec/logs/wazuh" ]; then
        find /var/ossec/logs/wazuh -type f -name "*.log" -exec cat /dev/null > {} \; 2>/dev/null
        log_action "Cleared Wazuh logs"
    fi
    
    # Clean SELinux audit logs if present
    if [ -f "/var/log/audit/audit.log" ]; then
        cat /dev/null > /var/log/audit/audit.log 2>/dev/null
        log_action "Cleared SELinux audit logs"
    fi
    
    # Clean fail2ban logs if present
    if [ -d "/var/log/fail2ban" ]; then
        cat /dev/null > /var/log/fail2ban.log 2>/dev/null
        log_action "Cleared fail2ban logs"
    fi
    
    show_notification "Audit logs and monitoring traces cleaned" "success"
    return 0
}

# Function to clean containerization and virtualization traces
clean_container_traces() {
    show_notification "Cleaning containerization and virtualization traces..." "info"
    log_action "Started cleaning containerization traces"
    
    # Clean Docker logs and history
    if command_exists docker; then
        if confirm_action "Clean Docker logs and history?" "Y"; then
            docker system prune -f &>/dev/null
            
            # Remove all container logs
            if [ -d "/var/lib/docker/containers" ]; then
                find /var/lib/docker/containers -name "*-json.log" -exec cat /dev/null > {} \; 2>/dev/null
                log_action "Cleared Docker container logs"
            fi
            
            # Clear command history
            if [ -f "/root/.docker/config.json" ]; then
                # Backup config but remove history
                tmp_file=$(mktemp)
                jq 'del(.auths, .HttpHeaders, .psFormat)' /root/.docker/config.json > "$tmp_file" 2>/dev/null
                cat "$tmp_file" > /root/.docker/config.json
                rm -f "$tmp_file"
                log_action "Cleared Docker command history"
            fi
            
            show_notification "Docker traces cleaned" "success"
        fi
    fi
    
    # Clean LXC logs if present
    if [ -d "/var/log/lxc" ]; then
        find /var/log/lxc -name "*.log" -exec cat /dev/null > {} \; 2>/dev/null
        log_action "Cleared LXC logs"
        show_notification "LXC logs cleaned" "success"
    fi
    
    # Clean libvirt logs if present
    if [ -d "/var/log/libvirt" ]; then
        find /var/log/libvirt -name "*.log" -exec cat /dev/null > {} \; 2>/dev/null
        log_action "Cleared libvirt logs"
        show_notification "Libvirt logs cleaned" "success"
    fi
    
    # Clean KVM/QEMU logs if present
    if [ -d "/var/log/qemu" ]; then
        find /var/log/qemu -name "*.log" -exec cat /dev/null > {} \; 2>/dev/null
        log_action "Cleared QEMU logs"
        show_notification "QEMU logs cleaned" "success"
    fi
    
    return 0
}

# Main function to handle deep cleaning operations
handle_deep_cleaning() {
    clear
    display_section_header "Advanced Trace Elimination"
    
    local options=(
        "Clean Memory Artifacts"
        "Clean Process History"
        "Clean Temporary Files and Caches"
        "Clean Filesystem Traces"
        "Clean Network Traces"
        "Clean Application-Specific Traces"
        "Clean Audit Logs and Monitoring"
        "Clean Containerization Traces"
        "Complete Deep Clean (All of the Above)"
        "Return to Main Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" choice

    case $choice in
        1) 
            clean_memory_artifacts
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_deep_cleaning
            ;;
        2) 
            clean_process_history
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_deep_cleaning
            ;;
        3) 
            clean_temps_and_caches
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_deep_cleaning
            ;;
        4) 
            clean_filesystem_traces
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_deep_cleaning
            ;;
        5) 
            clean_network_traces
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_deep_cleaning
            ;;
        6) 
            clean_application_traces
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_deep_cleaning
            ;;
        7) 
            clean_audit_traces
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_deep_cleaning
            ;;
        8) 
            clean_container_traces
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_deep_cleaning
            ;;
        9)
            # Execute all cleaning functions
            show_notification "Starting comprehensive deep cleaning..." "info"
            clean_memory_artifacts
            clean_process_history
            clean_temps_and_caches
            clean_filesystem_traces
            clean_network_traces
            clean_application_traces
            clean_audit_traces
            clean_container_traces
            show_notification "Comprehensive deep cleaning completed" "success"
            
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_deep_cleaning
            ;;
        10) return 0 ;;
        *)
            show_notification "Invalid option" "error"
            sleep 1
            handle_deep_cleaning
            ;;
    esac
} 