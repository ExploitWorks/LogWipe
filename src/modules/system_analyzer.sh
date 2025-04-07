#!/bin/bash

# Advanced system analyzer module for LogWipe

# Function to analyze system logs
analyze_system_logs() {
    clear
    display_section_header "System Log Analysis"
    
    show_notification "Analyzing system logs..." "info"
    log_action "Started system log analysis"
    
    # Start progress bar
    for i in {1..20}; do
        show_progress 20 $i "Processing logs"
        sleep 0.1
    done
    
    # Check for authentication failures
    echo -e "\n${YELLOW}--- Authentication Failures ---${NC}"
    grep -i "failed\|failure\|invalid" /var/log/auth.log 2>/dev/null | tail -n 10 | 
        while read line; do
            echo -e "${RED}$line${NC}"
        done
    
    # Check for system errors
    echo -e "\n${YELLOW}--- System Errors ---${NC}"
    grep -i "error\|critical\|failure\|fail" /var/log/syslog 2>/dev/null | tail -n 10 |
        while read line; do
            echo -e "${PURPLE}$line${NC}"
        done
    
    # Check for suspicious activities
    echo -e "\n${YELLOW}--- Suspicious Activities ---${NC}"
    grep -i "unauthorized\|suspicious\|violation\|attack" /var/log/syslog /var/log/auth.log 2>/dev/null | tail -n 10 |
        while read line; do
            echo -e "${RED}$line${NC}"
        done
    
    # Summary of recent logins
    echo -e "\n${YELLOW}--- Recent Logins ---${NC}"
    last | head -n 10 |
        while read line; do
            echo -e "${CYAN}$line${NC}"
        done
    
    echo ""
    show_notification "Analysis completed." "success"
    log_action "Completed system log analysis"
    
    echo ""
    read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    return 0
}

# Function to perform security audit
security_audit() {
    clear
    display_section_header "Security Audit"
    
    show_notification "Performing security audit..." "info"
    log_action "Started security audit"
    
    # Start progress bar
    for i in {1..20}; do
        show_progress 20 $i "Analyzing security"
        sleep 0.1
    done
    
    # Check for failed login attempts
    echo -e "\n${YELLOW}--- Failed Login Attempts ---${NC}"
    echo -e "${WHITE}Last 10 failed login attempts:${NC}"
    grep -i "failed password" /var/log/auth.log 2>/dev/null | tail -n 10 |
        while read line; do
            echo -e "${RED}$line${NC}"
        done
    
    # Check for sudo usage
    echo -e "\n${YELLOW}--- Sudo Usage ---${NC}"
    echo -e "${WHITE}Last 10 sudo commands:${NC}"
    grep -i "sudo" /var/log/auth.log 2>/dev/null | tail -n 10 |
        while read line; do
            echo -e "${CYAN}$line${NC}"
        done
    
    # Check for filesystem changes
    echo -e "\n${YELLOW}--- File System Changes ---${NC}"
    echo -e "${WHITE}Last 10 modified files in /etc:${NC}"
    find /etc -type f -mtime -7 2>/dev/null | head -n 10 |
        while read line; do
            echo -e "${PURPLE}$line${NC}"
        done
    
    # Check for listening ports
    echo -e "\n${YELLOW}--- Open Ports ---${NC}"
    echo -e "${WHITE}Current listening ports:${NC}"
    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null |
        while read line; do
            echo -e "${GREEN}$line${NC}"
        done
    
    # Check for suspicious processes
    echo -e "\n${YELLOW}--- Top CPU Processes ---${NC}"
    ps aux --sort=-%cpu | head -n 10 |
        while read line; do
            echo -e "${CYAN}$line${NC}"
        done
    
    echo ""
    show_notification "Security audit completed." "success"
    log_action "Completed security audit"
    
    echo ""
    read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    return 0
}

# Function to analyze log sizes
analyze_log_sizes() {
    clear
    display_section_header "Log Size Analysis"
    
    show_notification "Analyzing log sizes..." "info"
    log_action "Started log size analysis"
    
    # Start progress bar
    for i in {1..20}; do
        show_progress 20 $i "Calculating sizes"
        sleep 0.1
    done
    
    echo -e "\n${YELLOW}--- Largest Log Files ---${NC}"
    find /var/log -type f -exec du -h {} \; 2>/dev/null | sort -hr | head -n 20 |
        while read line; do
            echo -e "${CYAN}$line${NC}"
        done
    
    echo -e "\n${YELLOW}--- Log Directory Size ---${NC}"
    du -sh /var/log 2>/dev/null |
        while read line; do
            echo -e "${GREEN}$line${NC}"
        done
    
    echo -e "\n${YELLOW}--- Log Rotation Status ---${NC}"
    ls -la /var/log/*.gz /var/log/*.1 2>/dev/null | tail -n 10 |
        while read line; do
            echo -e "${PURPLE}$line${NC}"
        done
    
    echo ""
    show_notification "Log size analysis completed." "success"
    log_action "Completed log size analysis"
    
    echo ""
    read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    return 0
}

# Function to generate activity timeline
generate_timeline() {
    clear
    display_section_header "Activity Timeline"
    
    show_notification "Generating activity timeline..." "info"
    log_action "Started timeline generation"
    
    # Define temporary file
    local temp_file="/tmp/logwipe_timeline.txt"
    
    # Clear temp file
    > "$temp_file"
    
    # Collect various logs with timestamps with progress indicators
    echo -e "\n${YELLOW}Collecting logs...${NC}"
    
    local steps=3
    local current_step=0
    
    show_notification "Collecting auth logs..." "info"
    grep -E "^[A-Za-z]+ [0-9]+ [0-9:]+" /var/log/auth.log 2>/dev/null >> "$temp_file"
    show_progress $steps $((++current_step)) "Processing log files"
    
    show_notification "Collecting system logs..." "info"
    grep -E "^[A-Za-z]+ [0-9]+ [0-9:]+" /var/log/syslog 2>/dev/null >> "$temp_file"
    show_progress $steps $((++current_step)) "Processing log files"
    
    show_notification "Collecting kernel logs..." "info"
    grep -E "^[A-Za-z]+ [0-9]+ [0-9:]+" /var/log/kern.log 2>/dev/null >> "$temp_file"
    show_progress $steps $((++current_step)) "Processing log files"
    
    # Sort all entries by date and time
    show_notification "Sorting timeline entries..." "info"
    sort -k1,2 "$temp_file" > "${temp_file}.sorted"
    
    # Display the timeline
    echo -e "\n${YELLOW}--- Recent Activity Timeline (Last 50 Events) ---${NC}"
    tail -n 50 "${temp_file}.sorted" |
        while read line; do
            # Colorize based on content
            if [[ "$line" == *"error"* || "$line" == *"fail"* || "$line" == *"denied"* ]]; then
                echo -e "${RED}$line${NC}"
            elif [[ "$line" == *"warning"* || "$line" == *"notice"* ]]; then
                echo -e "${YELLOW}$line${NC}"
            elif [[ "$line" == *"success"* || "$line" == *"started"* ]]; then
                echo -e "${GREEN}$line${NC}"
            else
                echo -e "${CYAN}$line${NC}"
            fi
        done
    
    # Clean up
    rm -f "$temp_file" "${temp_file}.sorted"
    
    echo ""
    show_notification "Timeline generation completed." "success"
    log_action "Completed timeline generation"
    
    echo ""
    read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    return 0
} 