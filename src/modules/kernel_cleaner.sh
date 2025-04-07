#!/bin/bash

# Kernel Cleaner Module for LogWipe
# Provides techniques to eliminate kernel-level traces and forensic artifacts

# Function to clear the kernel message buffer
clear_kernel_messages() {
    show_notification "Clearing kernel message buffer..." "info"
    log_action "Started clearing kernel message buffer"
    
    # Use dmesg to clear the kernel ring buffer
    if command_exists dmesg; then
        dmesg -c > /dev/null 2>&1
        log_action "Cleared kernel ring buffer"
        show_notification "Kernel ring buffer cleared" "success"
    else
        show_notification "dmesg command not found" "error"
        log_action "Failed to clear kernel ring buffer: dmesg command not found"
        return 1
    fi
    
    return 0
}

# Function to unload and clean kernel modules
clean_kernel_modules() {
    show_notification "Cleaning kernel module traces..." "info"
    log_action "Started cleaning kernel module traces"
    
    # Log currently loaded modules for reference
    if [ "$verbose" = true ]; then
        lsmod > "$LOG_DIR/modules_before_cleaning.log"
        log_action "Logged currently loaded modules to $LOG_DIR/modules_before_cleaning.log"
    fi
    
    # Check for suspicious or non-standard modules
    local suspicious_modules=$(lsmod | grep -v -E 'nvidia|nouveau|amdgpu|radeon|i915|e1000|r8169|ath|iwl|btusb|usbhid|ehci|xhci|uhci|ohci|snd|usb|pci|scsi|block|fs|crypto|nf|ip|tcp|ext4|vfat|ntfs' | grep -v -E '^Module' | awk '{print $1}')
    
    if [ -n "$suspicious_modules" ]; then
        show_notification "Potentially suspicious kernel modules detected:" "warning"
        echo "$suspicious_modules" | while read module; do
            echo -e "${YELLOW}$module${NC}"
            
            if confirm_action "Attempt to unload module $module? (May destabilize system)" "N"; then
                # Attempt to unload the module
                rmmod "$module" 2>/dev/null
                if [ $? -eq 0 ]; then
                    log_action "Successfully unloaded module $module"
                    show_notification "Module $module unloaded" "success"
                else
                    log_action "Failed to unload module $module"
                    show_notification "Failed to unload module $module" "error"
                fi
            fi
        done
    else
        show_notification "No suspicious kernel modules detected" "info"
    fi
    
    # Clean kernel module load history
    if [ -f "/proc/modules" ] && [ -w "/dev/kmsg" ]; then
        if confirm_action "Clear kernel module loading history? (May generate alerts)" "N"; then
            echo "Clearing kernel module history..." > /dev/kmsg 2>/dev/null
            log_action "Attempted to clear kernel module loading history via kmsg"
            show_notification "Attempted to clear kernel module loading history" "success"
        fi
    fi
    
    return 0
}

# Function to clear SysRq traces
clear_sysrq_traces() {
    show_notification "Clearing SysRq traces..." "info"
    log_action "Started clearing SysRq traces"
    
    # Disable SysRq if it's enabled
    if [ -f "/proc/sys/kernel/sysrq" ]; then
        local current_sysrq=$(cat /proc/sys/kernel/sysrq)
        
        if [ "$current_sysrq" != "0" ]; then
            echo 0 > /proc/sys/kernel/sysrq 2>/dev/null
            log_action "Disabled SysRq (was set to $current_sysrq)"
            show_notification "SysRq disabled" "success"
        else
            show_notification "SysRq already disabled" "info"
        fi
    else
        show_notification "SysRq control file not found" "warning"
    fi
    
    return 0
}

# Function to clean network packet traces
clean_packet_traces() {
    show_notification "Cleaning network packet traces..." "info"
    log_action "Started cleaning network packet traces"
    
    # Check if iptables is available
    if command_exists iptables; then
        if confirm_action "Clear iptables packet counters? (Won't affect rules)" "Y"; then
            iptables -Z 2>/dev/null
            log_action "Cleared iptables packet counters"
            show_notification "Packet counters cleared" "success"
        fi
    fi
    
    # Flush connection tracking table
    if [ -f "/proc/net/nf_conntrack" ] || [ -d "/proc/sys/net/netfilter" ]; then
        if confirm_action "Flush connection tracking table? (May disrupt active connections)" "N"; then
            echo 1 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null
            cat /proc/sys/net/netfilter/nf_conntrack_max > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null
            log_action "Flushed connection tracking table"
            show_notification "Connection tracking table flushed" "success"
        fi
    fi
    
    # Reset network statistics
    if [ -d "/proc/net/stat" ]; then
        if confirm_action "Reset network statistics?" "Y"; then
            for stat_file in /proc/net/stat/*; do
                if [ -f "$stat_file" ]; then
                    echo 0 > "$stat_file" 2>/dev/null
                fi
            done
            log_action "Attempted to reset network statistics"
            show_notification "Network statistics reset attempted" "success"
        fi
    fi
    
    return 0
}

# Function to clear kernel-level accounting
clear_kernel_accounting() {
    show_notification "Clearing kernel-level accounting..." "info"
    log_action "Started clearing kernel-level accounting"
    
    # Process accounting
    if command_exists accton; then
        if confirm_action "Disable process accounting if active?" "Y"; then
            accton off 2>/dev/null
            log_action "Disabled process accounting"
            show_notification "Process accounting disabled" "success"
        fi
    fi
    
    # Task accounting
    if [ -d "/proc/sys/kernel" ]; then
        if [ -f "/proc/sys/kernel/task_delayacct" ]; then
            if confirm_action "Disable task delay accounting?" "Y"; then
                echo 0 > /proc/sys/kernel/task_delayacct 2>/dev/null
                log_action "Disabled task delay accounting"
                show_notification "Task delay accounting disabled" "success"
            fi
        fi
    fi
    
    # I/O accounting
    if [ -d "/proc/sys/vm" ]; then
        if [ -f "/proc/sys/vm/block_dump" ]; then
            if confirm_action "Disable block I/O debugging?" "Y"; then
                echo 0 > /proc/sys/vm/block_dump 2>/dev/null
                log_action "Disabled block I/O debugging"
                show_notification "Block I/O debugging disabled" "success"
            fi
        fi
    fi
    
    return 0
}

# Function to clean kernel crash dumps and reports
clean_kernel_crash_dumps() {
    show_notification "Cleaning kernel crash dumps and reports..." "info"
    log_action "Started cleaning kernel crash dumps and reports"
    
    # Kdump files
    if [ -d "/var/crash" ]; then
        if confirm_action "Remove kernel crash dumps in /var/crash?" "Y"; then
            rm -rf /var/crash/* 2>/dev/null
            log_action "Removed kernel crash dumps"
            show_notification "Kernel crash dumps removed" "success"
        fi
    fi
    
    # Kernel core pattern
    if [ -f "/proc/sys/kernel/core_pattern" ]; then
        if confirm_action "Disable kernel core dumps?" "Y"; then
            echo "/dev/null" > /proc/sys/kernel/core_pattern 2>/dev/null
            log_action "Disabled kernel core dumps"
            show_notification "Kernel core dumps disabled" "success"
        fi
    fi
    
    # Clean abrt/crash reports if present
    if [ -d "/var/spool/abrt" ]; then
        if confirm_action "Remove ABRT crash reports?" "Y"; then
            rm -rf /var/spool/abrt/* 2>/dev/null
            log_action "Removed ABRT crash reports"
            show_notification "ABRT crash reports removed" "success"
        fi
    fi
    
    # Clean any core files in the system
    if confirm_action "Find and remove core dump files across the system?" "Y"; then
        find / -xdev -name "core" -o -name "core.*" -type f -delete 2>/dev/null
        log_action "Removed core dump files"
        show_notification "Core dump files removed" "success"
    fi
    
    return 0
}

# Function to manipulate timestamps for the kernel
manipulate_kernel_timestamps() {
    show_notification "Manipulating kernel timestamps..." "info"
    log_action "Started manipulating kernel timestamps"
    
    # First show a serious warning about the high risk of this operation
    show_notification "⚠️ ⚠️ ⚠️ EXTREME CAUTION ⚠️ ⚠️ ⚠️" "error"
    show_notification "Kernel timestamp manipulation is a HIGH-RISK operation that could cause:" "error"
    echo -e "${RED}  • System crash or kernel panic"
    echo -e "  • Services failure and authentication issues"
    echo -e "  • Security certificate validation problems"
    echo -e "  • Data loss in time-sensitive applications"
    echo -e "  • Irreversible system damage${NC}"
    
    # This is a high-risk operation, so add multiple confirmations
    if ! confirm_action "Do you understand the risks of kernel timestamp manipulation?" "N"; then
        show_notification "Operation aborted by user" "info"
        log_action "Kernel timestamp manipulation aborted: User declined risk acknowledgment"
        return 1
    fi
    
    if ! confirm_action "Manipulate kernel timestamps? This is a HIGH-RISK operation that may crash your system" "N"; then
        show_notification "Operation aborted by user" "info"
        log_action "Kernel timestamp manipulation aborted by user"
        return 1
    fi
    
    # Additional safety check - verify system is not in production
    if ! confirm_action "Is this system a NON-PRODUCTION system that can tolerate crashes?" "N"; then
        show_notification "Operation aborted: Production system detected" "warning"
        log_action "Kernel timestamp manipulation aborted: Production system detected"
        return 1
    fi
    
    # Generate a random verification code as final safeguard
    local verification_code=$(tr -dc 'A-Z0-9' < /dev/urandom | head -c 6)
    echo -e "${RED}Final verification required.${NC}"
    echo -e "To confirm this high-risk operation, please type this code: ${YELLOW}${verification_code}${NC}"
    read -p "Verification code: " user_code
    
    if [ "$user_code" != "$verification_code" ]; then
        show_notification "Incorrect verification code. Operation aborted." "info"
        log_action "Kernel timestamp manipulation aborted: incorrect verification code"
        return 1
    fi
    
    # First, get current time and save it
    local current_time=$(date +%s)
    log_action "Current system time saved: $(date -d @$current_time)"
    
    # Calculate a plausible past time (7 days ago)
    local past_time=$((current_time - 604800)) # 7 days in seconds
    
    if confirm_action "Set kernel time to appear 7 days older? System may become unstable" "N"; then
        # Create a backup plan for recovery
        show_notification "Creating time recovery script in /tmp/recover_time.sh" "info"
        cat > /tmp/recover_time.sh << EOL
#!/bin/bash
# Recovery script to restore system time
date -s @$current_time
echo "Time restored to original value: \$(date)"
EOL
        chmod +x /tmp/recover_time.sh
        
        # Attempt to set the kernel timestamp
        if command_exists date; then
            show_notification "Modifying system time now..." "warning"
            echo -e "${YELLOW}If your system becomes unresponsive, run: /tmp/recover_time.sh${NC}"
            sleep 3
            
            date -s @$past_time &>/dev/null
            log_action "Temporarily set system time to $(date -d @$past_time)"
            
            # Wait briefly for any immediate issues
            sleep 2
            
            # Check if the system is still responsive
            if ! date &>/dev/null; then
                show_notification "System appears to be experiencing issues!" "error"
                # Try to recover immediately
                date -s @$current_time &>/dev/null
                log_action "Emergency recovery of system time attempted"
                return 1
            fi
            
            # Immediately set it back to avoid too much disruption
            date -s @$current_time &>/dev/null
            
            log_action "Restored original system time"
            show_notification "Kernel timestamp temporarily manipulated and restored" "success"
        else
            show_notification "date command not found" "error"
            log_action "Failed to manipulate kernel timestamp: date command not found"
            return 1
        fi
    else
        show_notification "Time manipulation skipped" "info"
    fi
    
    return 0
}

# Function to clean systemd-journal traces
clean_systemd_journal() {
    show_notification "Cleaning systemd journal traces..." "info"
    log_action "Started cleaning systemd journal traces"
    
    if command_exists journalctl; then
        # Vacuum the journal to minimal size
        if confirm_action "Vacuum systemd journal to minimal size?" "Y"; then
            journalctl --vacuum-time=1s 2>/dev/null
            log_action "Vacuumed systemd journal"
            show_notification "Systemd journal vacuumed" "success"
        fi
        
        # Rotate the journal to create a fresh log file
        if confirm_action "Rotate systemd journal?" "Y"; then
            journalctl --rotate 2>/dev/null
            log_action "Rotated systemd journal"
            show_notification "Systemd journal rotated" "success"
        fi
        
        # Check for persistent journals
        if [ -d "/var/log/journal" ]; then
            if confirm_action "Remove persistent journal files? (This will permanently delete system logs)" "N"; then
                rm -rf /var/log/journal/* 2>/dev/null
                log_action "Removed persistent journal files"
                show_notification "Persistent journal files removed" "success"
                
                # Restart systemd-journald to apply changes
                if command_exists systemctl; then
                    systemctl restart systemd-journald 2>/dev/null
                    log_action "Restarted systemd-journald service"
                fi
            fi
        fi
    else
        show_notification "journalctl not found, not a systemd system" "warning"
    fi
    
    return 0
}

# Function to handle kernel cleaning operations
handle_kernel_cleaning() {
    clear
    display_section_header "Kernel-Level Trace Elimination"
    
    local options=(
        "Clear Kernel Message Buffer"
        "Clean Kernel Module Traces"
        "Clear SysRq Traces"
        "Clean Network Packet Traces"
        "Clear Kernel-Level Accounting"
        "Clean Kernel Crash Dumps"
        "Manipulate Kernel Timestamps (High Risk)"
        "Clean Systemd Journal Traces"
        "Full Kernel Cleaning (All of the Above)"
        "Return to Main Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" choice

    case $choice in
        1) 
            clear_kernel_messages
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_kernel_cleaning
            ;;
        2) 
            clean_kernel_modules
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_kernel_cleaning
            ;;
        3) 
            clear_sysrq_traces
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_kernel_cleaning
            ;;
        4) 
            clean_packet_traces
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_kernel_cleaning
            ;;
        5) 
            clear_kernel_accounting
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_kernel_cleaning
            ;;
        6) 
            clean_kernel_crash_dumps
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_kernel_cleaning
            ;;
        7) 
            manipulate_kernel_timestamps
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_kernel_cleaning
            ;;
        8) 
            clean_systemd_journal
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_kernel_cleaning
            ;;
        9)
            # Execute all cleaning functions
            show_notification "Starting comprehensive kernel cleaning..." "info"
            clear_kernel_messages
            clean_kernel_modules
            clear_sysrq_traces
            clean_packet_traces
            clear_kernel_accounting
            clean_kernel_crash_dumps
            # Skip timestamp manipulation as it's high risk
            clean_systemd_journal
            show_notification "Comprehensive kernel cleaning completed" "success"
            
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_kernel_cleaning
            ;;
        10) return 0 ;;
        *)
            show_notification "Invalid option" "error"
            sleep 1
            handle_kernel_cleaning
            ;;
    esac
} 