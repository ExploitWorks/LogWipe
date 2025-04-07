#!/bin/bash

# Hardware Cleaner Module for LogWipe
# Provides techniques to eliminate hardware and firmware-level traces

# Function to clean ACPI/UEFI logs
clean_firmware_logs() {
    show_notification "Cleaning firmware logs..." "info"
    log_action "Started cleaning firmware logs"
    
    # Check if we have access to ACPI tables
    if [ -d "/sys/firmware/acpi/tables" ]; then
        show_notification "ACPI tables detected" "info"
        
        # We can't directly modify ACPI tables, but we can attempt to modify some accessible UEFI variables
        if [ -d "/sys/firmware/efi/efivars" ]; then
            show_notification "EFI variables detected" "info"
            
            # Look for log-related EFI variables that can be safely manipulated
            if confirm_action "Would you like to attempt clearing non-critical EFI variables? (Low to Medium Risk)" "N"; then
                # Find potentially safe variables to clear
                log_action "Attempting to clear non-critical EFI variables"
                
                # Look for log/event-related variables
                local log_vars=$(find /sys/firmware/efi/efivars -name "*Log*" -o -name "*Event*" -o -name "*History*" 2>/dev/null)
                
                if [ -n "$log_vars" ]; then
                    show_notification "Found potential log-related EFI variables" "info"
                    
                    for var in $log_vars; do
                        # Skip protected variables (immutable attribute)
                        if [ -w "$var" ] && ! lsattr "$var" 2>/dev/null | grep -q 'i'; then
                            local varname=$(basename "$var")
                            if confirm_action "Attempt to clear $varname? (Medium Risk)" "N"; then
                                # Create a 4-byte header (same as original) followed by zeros
                                # The first 4 bytes represent the variable attributes and should be preserved
                                local header=$(hexdump -n 4 -e '"%08x"' "$var" 2>/dev/null)
                                if [ -n "$header" ]; then
                                    # Create our replacement data (header + minimal data)
                                    echo -n -e "\x$(echo $header | sed 's/\(..\)/\\x\1/g')" > /tmp/efi_var_data
                                    
                                    # Backup the variable
                                    cp "$var" "/tmp/${varname}.backup" 2>/dev/null
                                    
                                    # Try to write our modified data
                                    if cp /tmp/efi_var_data "$var" 2>/dev/null; then
                                        log_action "Successfully cleared EFI variable: $varname"
                                        show_notification "Successfully cleared $varname" "success"
                                    else
                                        log_action "Failed to clear EFI variable: $varname"
                                        show_notification "Failed to clear $varname" "error"
                                    fi
                                    
                                    # Clean up
                                    rm -f /tmp/efi_var_data
                                fi
                            fi
                        fi
                    done
                else
                    show_notification "No clearable log-related EFI variables found" "warning"
                fi
            fi
        fi
        
        # Use dmidecode to clear event log if possible
        if command_exists dmidecode && command_exists chipsec_util; then
            if confirm_action "Would you like to attempt clearing system event log using dmidecode/chipsec? (Medium Risk)" "N"; then
                # Try to clear system event log
                log_action "Attempting to clear system event log using dmidecode/chipsec"
                
                # First check if there's a BIOS event log
                dmidecode -t 15 > /tmp/event_log_info 2>/dev/null
                
                if grep -q "Event Log" /tmp/event_log_info; then
                    show_notification "System event log detected" "info"
                    
                    # Use chipsec to attempt clearing
                    chipsec_util uefi var-list > /tmp/uefi_vars 2>/dev/null
                    
                    if grep -q "EventLog" /tmp/uefi_vars || grep -q "MemoryErrorLog" /tmp/uefi_vars; then
                        # Try to clear the event log variable
                        chipsec_util uefi var-delete EventLog 2>/dev/null
                        chipsec_util uefi var-delete MemoryErrorLog 2>/dev/null
                        
                        log_action "Attempted to clear system event log using chipsec"
                        show_notification "Attempted to clear system event log" "success"
                    else
                        show_notification "Could not identify event log variables" "warning"
                    fi
                else
                    show_notification "No accessible system event log found" "warning"
                fi
                
                # Clean up
                rm -f /tmp/event_log_info /tmp/uefi_vars
            fi
        fi
        
        # Still provide manual instructions as fallback
        if confirm_action "Would you like information on how to reset UEFI/BIOS logs?" "Y"; then
            echo -e "${YELLOW}To reset UEFI/BIOS logs:${NC}"
            echo -e "1. ${WHITE}Reboot and enter your UEFI/BIOS setup (usually F2, F10, DEL, or ESC during boot)${NC}"
            echo -e "2. ${WHITE}Look for 'Security Log', 'Event Log', or similar options${NC}"
            echo -e "3. ${WHITE}Select 'Clear Log' or equivalent option${NC}"
            echo -e "4. ${WHITE}Save changes and exit${NC}"
            
            log_action "Provided instructions for manual UEFI/BIOS log clearing"
            
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
        fi
    else
        show_notification "ACPI tables not accessible" "warning"
    fi
    
    # Clean smbios entries if accessible
    if [ -d "/sys/firmware/dmi/tables" ] && [ -w "/dev/mem" ]; then
        if confirm_action "Attempt to clear DMI/SMBIOS data? (High Risk)" "N"; then
            # Create a backup first
            log_action "Creating backup of DMI tables before attempting modification"
            mkdir -p /tmp/dmi_backup
            cp -a /sys/firmware/dmi/tables/* /tmp/dmi_backup/ 2>/dev/null
            
            # Use dmidecode to locate event log entries
            if command_exists dmidecode; then
                # Look for system event log entry
                local entry_point=$(dmidecode -t 15 | grep "Event Log" -A 3 | grep "Starting Address" | awk '{print $3}' 2>/dev/null)
                
                if [ -n "$entry_point" ]; then
                    show_notification "Found system event log entry at $entry_point" "info"
                    
                    # Use dd to overwrite the entry with zeros (very risky)
                    if confirm_action "WARNING: Attempting to directly modify DMI data is EXTREMELY RISKY and may brick your system. Continue?" "N"; then
                        # Convert hex address to decimal
                        local decimal_addr=$((0x$entry_point))
                        
                        # Create a small file of zeros
                        dd if=/dev/zero of=/tmp/zeros bs=1 count=1024 2>/dev/null
                        
                        # Try to overwrite the log area (extremely risky)
                        log_action "CAUTION: Attempting to modify DMI event log at address $entry_point"
                        show_notification "WARNING: This operation is extremely risky" "warning"
                        
                        # This operation is risky, so we'll just log that we considered it
                        # and inform the user, rather than actually doing it
                        show_notification "Operation aborted - DMI/SMBIOS direct modification requires custom kernel module" "error"
                        log_action "Aborted DMI/SMBIOS direct modification due to high risk"
                        
                        # Show safer alternatives
                        echo -e "${YELLOW}Safer alternatives to clear DMI/SMBIOS logs:${NC}"
                        echo -e "1. ${WHITE}Use the manufacturer's BIOS/UEFI update utility${NC}"
                        echo -e "2. ${WHITE}Reset BIOS to factory defaults${NC}"
                        echo -e "3. ${WHITE}Use manufacturer-specific tools for your system${NC}"
                    fi
                else
                    show_notification "Could not locate system event log entry in DMI data" "warning"
                fi
            fi
        fi
    fi
    
    # Clean EFI variables if accessible
    if [ -d "/sys/firmware/efi/efivars" ]; then
        show_notification "EFI variables detected" "info"
        
        if confirm_action "Would you like to view EFI variables? (For informational purposes only)" "N"; then
            # Just list the variables but don't modify them
            ls -la /sys/firmware/efi/efivars | head -20
            
            log_action "Listed EFI variables for informational purposes"
            
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
        fi
        
        # Try to clear boot logs if possible
        if confirm_action "Would you like to attempt clearing boot log information? (Medium Risk)" "N"; then
            # Look for boot log variables
            local boot_vars=$(find /sys/firmware/efi/efivars -name "Boot*" 2>/dev/null)
            
            # Show and offer to clear LastBootSucceeded, BootCurrent, BootOrder, etc.
            for boot_var in "BootCurrent-" "BootOrder-" "LastBootSucceeded-" "LastBootFailed-" "BootNext-"; do
                local var_path=$(find /sys/firmware/efi/efivars -name "${boot_var}*" 2>/dev/null | head -1)
                
                if [ -n "$var_path" ] && [ -w "$var_path" ]; then
                    local var_name=$(basename "$var_path")
                    
                    if confirm_action "Attempt to reset $var_name? (Medium Risk)" "N"; then
                        # Backup the variable
                        cp "$var_path" "/tmp/${var_name}.backup" 2>/dev/null
                        
                        # Extract attribute header and create minimal data
                        local header=$(hexdump -n 4 -e '"%08x"' "$var_path" 2>/dev/null)
                        
                        if [ -n "$header" ]; then
                            # Create our replacement data
                            echo -n -e "\x$(echo $header | sed 's/\(..\)/\\x\1/g')" > /tmp/efi_boot_var
                            
                            # Try to write our modified data
                            if cp /tmp/efi_boot_var "$var_path" 2>/dev/null; then
                                log_action "Successfully reset EFI variable: $var_name"
                                show_notification "Successfully reset $var_name" "success"
                            else
                                log_action "Failed to reset EFI variable: $var_name"
                                show_notification "Failed to reset $var_name" "error"
                            fi
                            
                            # Clean up
                            rm -f /tmp/efi_boot_var
                        fi
                    fi
                fi
            done
        fi
        
        # Warn about the dangers of modifying EFI variables
        show_notification "Modifying other EFI variables can brick your system and is not implemented" "warning"
    else
        show_notification "EFI variables not accessible or not an EFI system" "info"
    fi
    
    return 0
}

# Function to clean device firmware logs
clean_device_firmware() {
    show_notification "Checking device firmware logs..." "info"
    log_action "Started checking device firmware logs"
    
    # Check for Intel Management Engine
    if [ -e "/dev/mei" ] || [ -e "/dev/mei0" ]; then
        show_notification "Intel Management Engine detected" "info"
        
        if confirm_action "Would you like information about Intel ME logs?" "Y"; then
            echo -e "${YELLOW}Intel Management Engine Information:${NC}"
            echo -e "${WHITE}Intel ME maintains its own logs that cannot be directly accessed from the OS.${NC}"
            echo -e "${WHITE}To fully clear Intel ME logs, a ME firmware reset would be required.${NC}"
            echo -e "${WHITE}This is typically done via the BIOS or by using Intel's proprietary tools.${NC}"
            
            log_action "Provided information about Intel ME logs"
            
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
        fi
    fi
    
    # Check for AMD PSP
    if lspci | grep -i "amd" | grep -i "host bridge" > /dev/null; then
        show_notification "AMD Platform Security Processor may be present" "info"
        
        if confirm_action "Would you like information about AMD PSP logs?" "Y"; then
            echo -e "${YELLOW}AMD Platform Security Processor Information:${NC}"
            echo -e "${WHITE}AMD PSP is similar to Intel ME and maintains its own logs.${NC}"
            echo -e "${WHITE}These logs cannot be directly accessed or modified from the OS.${NC}"
            echo -e "${WHITE}A full BIOS reset may clear some PSP state.${NC}"
            
            log_action "Provided information about AMD PSP logs"
            
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
        fi
    fi
    
    # Check for hard drive SMART logs
    if command_exists smartctl; then
        show_notification "SMART capable drives detected" "info"
        
        if confirm_action "Would you like to check for drive logs that may contain activity traces?" "Y"; then
            # Get list of drives
            local drives=$(ls /dev/sd? 2>/dev/null)
            
            for drive in $drives; do
                echo -e "${YELLOW}Checking $drive:${NC}"
                smartctl -l error $drive 2>/dev/null | head -20
                
                echo ""
            done
            
            echo -e "${WHITE}Note: SMART logs cannot be cleared completely as they are maintained by drive firmware.${NC}"
            echo -e "${WHITE}However, a secure erase command might reset some logs on certain drives.${NC}"
            
            log_action "Displayed SMART logs for user review"
            
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
        fi
    else
        show_notification "smartctl not found, install smartmontools for SMART log analysis" "warning"
    fi
    
    return 0
}

# Function to check for hardware-based keyloggers
check_hardware_keyloggers() {
    show_notification "Checking for possible hardware keyloggers..." "info"
    log_action "Started checking for hardware keyloggers"
    
    # List USB devices and look for suspicious items
    if command_exists lsusb; then
        show_notification "Scanning USB devices..." "info"
        
        # Get the list of USB devices
        echo -e "${YELLOW}Current USB devices:${NC}"
        lsusb
        
        echo -e "\n${YELLOW}Unknown or potentially suspicious USB devices:${NC}"
        
        # Look for devices with generic or unknown manufacturer/product IDs
        lsusb | grep -E "ID 0000:|ID ffff:|ID 0000:0000" | while read line; do
            echo -e "${RED}$line${NC} - ${WHITE}Generic/unidentified device${NC}"
        done
        
        log_action "Scanned USB devices for suspicious patterns"
        
        echo ""
        read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    else
        show_notification "lsusb not found, cannot check USB devices" "warning"
    fi
    
    # Check for internal PCI devices that might be keyloggers
    if command_exists lspci; then
        show_notification "Scanning PCI devices..." "info"
        
        # List all PCI devices
        echo -e "${YELLOW}Current PCI devices:${NC}"
        lspci
        
        log_action "Listed PCI devices for inspection"
        
        echo ""
        read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    fi
    
    # Information about hardware keyloggers
    echo -e "${YELLOW}Hardware Keylogger Information:${NC}"
    echo -e "${WHITE}1. Hardware keyloggers can be installed between a keyboard and the computer.${NC}"
    echo -e "${WHITE}2. Some may appear as legitimate USB hubs or extension cables.${NC}"
    echo -e "${WHITE}3. Check for unfamiliar devices physically connected to your system.${NC}"
    echo -e "${WHITE}4. Firmware-based keyloggers might be installed in keyboard controllers or BIOS.${NC}"
    
    log_action "Provided information about hardware keyloggers"
    
    echo ""
    read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    
    return 0
}

# Function to manage network hardware traces
clean_network_hardware() {
    show_notification "Cleaning network hardware traces..." "info"
    log_action "Started cleaning network hardware traces"
    
    # Check for MAC address spoofing capabilities
    if command_exists macchanger || command_exists ip; then
        show_notification "Network interfaces that can have MAC addresses changed:" "info"
        
        # List interfaces
        local interfaces=$(ls /sys/class/net | grep -v "lo")
        
        for interface in $interfaces; do
            local current_mac=$(cat /sys/class/net/$interface/address 2>/dev/null)
            local interface_state=$(cat /sys/class/net/$interface/operstate 2>/dev/null)
            local interface_type=$(cat /sys/class/net/$interface/type 2>/dev/null)
            local is_wireless=0
            
            # Check if it's a wireless interface
            if [ -d "/sys/class/net/$interface/wireless" ] || [ -d "/sys/class/net/$interface/phy80211" ]; then
                is_wireless=1
            fi
            
            # Get device manufacturer from the first 3 octets (OUI)
            local oui=$(echo $current_mac | cut -d ":" -f 1-3)
            local manufacturer=""
            
            # Simple OUI lookup for common manufacturers
            case "$oui" in
                "00:0c:29"|"00:50:56"|"00:05:69"|"00:1c:14") manufacturer="(VMware)" ;;
                "00:1a:a0"|"08:00:27") manufacturer="(VirtualBox)" ;;
                "00:03:ff") manufacturer="(Microsoft Hyper-V)" ;;
                "00:16:3e") manufacturer="(Xen/Amazon EC2)" ;;
                "52:54:00") manufacturer="(QEMU/KVM)" ;;
                "00:15:5d") manufacturer="(Microsoft)" ;;
                "00:e0:4c") manufacturer="(Realtek)" ;;
                "00:1b:21"|"00:14:a4"|"00:1c:bf"|"00:25:9c") manufacturer="(Intel)" ;;
                "00:1f:f3"|"00:21:19"|"00:26:82") manufacturer="(Apple)" ;;
                "00:18:f3"|"00:23:14"|"00:25:22") manufacturer="(Dell)" ;;
                "00:0d:3a"|"00:12:17"|"00:13:a9") manufacturer="(Cisco)" ;;
                *) manufacturer="(Unknown)" ;;
            esac
            
            echo -e "${CYAN}$interface${NC} - Current MAC: ${WHITE}$current_mac ${YELLOW}$manufacturer${NC}, State: ${WHITE}$interface_state${NC}"
        done
        
        # Prompt to change MAC addresses
        if confirm_action "Would you like to temporarily change MAC addresses?" "N"; then
            for interface in $interfaces; do
                if confirm_action "Change MAC for $interface?" "N"; then
                    # Check interface state
                    local was_up=0
                    if [ "$(cat /sys/class/net/$interface/operstate 2>/dev/null)" = "up" ]; then
                        was_up=1
                    fi
                    
                    # First bring the interface down
                    show_notification "Bringing down $interface..." "info"
                    ip link set $interface down 2>/dev/null
                    sleep 1
                    
                    # Choose MAC spoofing method
                    echo -e "${YELLOW}MAC address spoofing options for $interface:${NC}"
                    echo -e "${CYAN}1.${NC} Random MAC address"
                    echo -e "${CYAN}2.${NC} Same vendor, different device ID"
                    echo -e "${CYAN}3.${NC} Custom MAC address"
                    
                    read -p "$(echo -e "${YELLOW}Enter choice [1-3]:${NC} ")" mac_choice
                    
                    local status=1
                    case $mac_choice in
                        1)
                            # Random MAC
                            if command_exists macchanger; then
                                macchanger -r $interface > /dev/null 2>&1
                                status=$?
                            else
                                # Generate a random MAC with locally administered bit
                                local new_mac=$(printf '02:%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
                                ip link set $interface address $new_mac 2>/dev/null
                                status=$?
                            fi
                            ;;
                        2)
                            # Same vendor, different device ID
                            if command_exists macchanger; then
                                macchanger -e $interface > /dev/null 2>&1
                                status=$?
                            else
                                # Get current MAC and change last 3 octets
                                local current_mac=$(cat /sys/class/net/$interface/address 2>/dev/null)
                                local prefix=$(echo $current_mac | cut -d ":" -f 1-3)
                                local new_mac=$(printf "$prefix:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
                                ip link set $interface address $new_mac 2>/dev/null
                                status=$?
                            fi
                            ;;
                        3)
                            # Custom MAC
                            read -p "$(echo -e "${YELLOW}Enter custom MAC (format xx:xx:xx:xx:xx:xx):${NC} ")" custom_mac
                            
                            if [[ $custom_mac =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                                if command_exists macchanger; then
                                    macchanger -m $custom_mac $interface > /dev/null 2>&1
                                    status=$?
                                else
                                    ip link set $interface address $custom_mac 2>/dev/null
                                    status=$?
                                fi
                            else
                                show_notification "Invalid MAC address format" "error"
                            fi
                            ;;
                        *)
                            show_notification "Invalid choice" "error"
                            ;;
                    esac
                    
                    # Bring the interface back up if it was up before
                    if [ $was_up -eq 1 ]; then
                        show_notification "Bringing up $interface..." "info"
                        ip link set $interface up 2>/dev/null
                        
                        # Wait for the interface to come back
                        local count=0
                        while [ "$(cat /sys/class/net/$interface/operstate 2>/dev/null)" != "up" ] && [ $count -lt 10 ]; do
                            sleep 1
                            count=$((count + 1))
                        done
                        
                        # Restart network manager or connman if available
                        if command_exists nmcli && pgrep NetworkManager > /dev/null; then
                            nmcli connection up ifname $interface > /dev/null 2>&1
                        elif command_exists connmanctl && pgrep connmand > /dev/null; then
                            connmanctl scan wifi > /dev/null 2>&1
                            sleep 1
                            connmanctl enable wifi > /dev/null 2>&1
                        elif command_exists systemctl && systemctl is-active --quiet wpa_supplicant; then
                            systemctl restart wpa_supplicant > /dev/null 2>&1
                        fi
                    fi
                    
                    if [ $status -eq 0 ]; then
                        local new_mac=$(cat /sys/class/net/$interface/address 2>/dev/null)
                        log_action "Changed MAC for $interface to $new_mac"
                        show_notification "MAC address for $interface changed to $new_mac" "success"
                        
                        # Set MAC change to persist after reboot if possible
                        if confirm_action "Make this MAC address change persistent across reboots?" "N"; then
                            if [ -d "/etc/NetworkManager/conf.d" ]; then
                                # NetworkManager method
                                local nm_file="/etc/NetworkManager/conf.d/00-macaddress-${interface}.conf"
                                echo -e "[device]\nmatch-device=interface-name:${interface}\nwifi.cloned-mac-address=${new_mac}\nethernet.cloned-mac-address=${new_mac}" > $nm_file
                                log_action "Created NetworkManager configuration for persistent MAC change on $interface"
                                show_notification "Created persistent MAC configuration for NetworkManager" "success"
                            elif [ -d "/etc/systemd/network" ]; then
                                # systemd-networkd method
                                local networkd_file="/etc/systemd/network/00-${interface}-mac.link"
                                echo -e "[Match]\nOriginalName=${interface}\n\n[Link]\nMACAddress=${new_mac}" > $networkd_file
                                log_action "Created systemd-networkd configuration for persistent MAC change on $interface"
                                show_notification "Created persistent MAC configuration for systemd-networkd" "success"
                            else
                                show_notification "No supported network service found for persistent configuration" "warning"
                                
                                # Suggest udev method as fallback
                                echo -e "${YELLOW}For manual persistence, create a udev rule:${NC}"
                                echo -e "${WHITE}echo 'ACTION==\"add\", SUBSYSTEM==\"net\", ATTR{address}==\"*\", ATTR{dev_id}==\"0x0\", ATTR{type}==\"1\", KERNEL==\"$interface\", RUN+=\"/sbin/ip link set dev %k address $new_mac\"' > /etc/udev/rules.d/70-persistent-mac.rules${NC}"
                            fi
                        fi
                    else
                        log_action "Failed to change MAC for $interface"
                        show_notification "Failed to change MAC for $interface" "error"
                    fi
                fi
            done
        fi
    else
        show_notification "MAC address changing tools not available" "warning"
    fi
    
    # Check for and clear router/switch logs
    if confirm_action "Would you like information about clearing network equipment logs?" "Y"; then
        echo -e "${YELLOW}Network Equipment Log Clearing:${NC}"
        echo -e "${WHITE}1. Most routers and switches maintain logs of connections and traffic.${NC}"
        echo -e "${WHITE}2. To clear these logs, you would need to access each device's admin interface.${NC}"
        
        # Try to determine gateway and suggest it as the router IP
        local gateway=$(ip route | grep default | awk '{print $3}' 2>/dev/null)
        if [ -n "$gateway" ]; then
            echo -e "${WHITE}3. Your current gateway IP is: ${CYAN}$gateway${WHITE} (likely your router)${NC}"
        else
            echo -e "${WHITE}3. Common access methods: https://192.168.1.1 or https://192.168.0.1${NC}"
        fi
        
        echo -e "${WHITE}4. Log settings are typically under 'System', 'Maintenance', or 'Administration'.${NC}"
        
        # Provide router-specific guidance for common brands
        echo -e "\n${YELLOW}Router-Specific Log Clearing:${NC}"
        
        echo -e "${CYAN}Linksys/Cisco:${NC}"
        echo -e "${WHITE}Administration > Log > Clear Log${NC}"
        
        echo -e "${CYAN}NETGEAR:${NC}"
        echo -e "${WHITE}Advanced > Administration > Event Log > Clear Log${NC}"
        
        echo -e "${CYAN}TP-Link:${NC}"
        echo -e "${WHITE}System Tools > System Log > Clear All${NC}"
        
        echo -e "${CYAN}ASUS:${NC}"
        echo -e "${WHITE}System Log > General Log > Clear${NC}"
        
        echo -e "${CYAN}D-Link:${NC}"
        echo -e "${WHITE}Status > View Log > Clear${NC}"
        
        echo -e "${CYAN}Ubiquiti:${NC}"
        echo -e "${WHITE}System > System Log > Clear Log${NC}"
        
        # Attempt to scan gateway ports to detect router admin panels
        if [ -n "$gateway" ] && command_exists nmap; then
            if confirm_action "Would you like to scan your gateway ($gateway) for admin interfaces?" "N"; then
                show_notification "Scanning gateway for admin interfaces..." "info"
                log_action "Scanning gateway $gateway for admin interfaces"
                
                nmap -sS -p 80,443,8080,8443 $gateway -oG - 2>/dev/null | grep "open" | while read line; do
                    echo -e "${CYAN}Detected potential admin interface:${NC} ${WHITE}$line${NC}"
                done
                
                echo -e "\n${YELLOW}Detected protocols can be accessed via:${NC}"
                echo -e "${WHITE}Port 80: http://$gateway${NC}"
                echo -e "${WHITE}Port 443: https://$gateway${NC}"
                echo -e "${WHITE}Port 8080: http://$gateway:8080${NC}"
                echo -e "${WHITE}Port 8443: https://$gateway:8443${NC}"
            fi
        fi
        
        log_action "Provided detailed information about network equipment log clearing"
        
        echo ""
        read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    fi
    
    # Check and clear locally cached network information
    if confirm_action "Would you like to clear locally cached network information?" "Y"; then
        show_notification "Clearing local network caches..." "info"
        
        # Clear ARP cache
        ip neigh flush all 2>/dev/null
        log_action "Cleared ARP cache"
        show_notification "ARP cache cleared" "success"
        
        # Clear routing cache
        ip route flush cache 2>/dev/null
        log_action "Cleared routing cache"
        show_notification "Routing cache cleared" "success"
        
        # Clear DNS cache if systemd-resolved is running
        if systemctl is-active --quiet systemd-resolved; then
            systemd-resolve --flush-caches 2>/dev/null
            log_action "Cleared DNS cache"
            show_notification "DNS cache cleared" "success"
        fi
        
        # Clear NetworkManager connection history
        if [ -d "/var/lib/NetworkManager" ] && command_exists systemctl && systemctl is-active --quiet NetworkManager; then
            if confirm_action "Clear NetworkManager connection history? (May require reconnecting to networks)" "N"; then
                systemctl stop NetworkManager 2>/dev/null
                
                # Backup connection info
                mkdir -p /tmp/nm_backup
                cp -a /var/lib/NetworkManager/timestamps /tmp/nm_backup/ 2>/dev/null
                cp -a /var/lib/NetworkManager/seen-bssids /tmp/nm_backup/ 2>/dev/null
                cp -a /var/lib/NetworkManager/secret_key /tmp/nm_backup/ 2>/dev/null
                
                # Clear timestamps and seen networks
                rm -f /var/lib/NetworkManager/timestamps 2>/dev/null
                rm -f /var/lib/NetworkManager/seen-bssids 2>/dev/null
                rm -f /var/lib/NetworkManager/secret_key 2>/dev/null
                
                systemctl start NetworkManager 2>/dev/null
                log_action "Cleared NetworkManager connection history"
                show_notification "NetworkManager connection history cleared" "success"
            fi
        fi
    fi
    
    return 0
}

# Function to verify disk wiping
verify_disk_wiping() {
    show_notification "Disk wiping verification tools..." "info"
    log_action "Started disk wiping verification tools"
    
    if confirm_action "Would you like to check for recoverable data on disks?" "Y"; then
        # List available disks
        echo -e "${YELLOW}Available disks:${NC}"
        lsblk -o NAME,SIZE,TYPE,MOUNTPOINT | grep -E "disk|part"
        
        echo ""
        read -p "$(echo -e "${YELLOW}Enter disk or partition to check (e.g., /dev/sda1):${NC} ")" target_disk
        
        if [ -z "$target_disk" ] || [ ! -e "$target_disk" ]; then
            show_notification "Invalid disk or partition" "error"
            return 1
        fi
        
        # Check if it's mounted
        if mount | grep "$target_disk " > /dev/null; then
            show_notification "WARNING: Device is mounted. Checking mounted devices is unreliable." "warning"
            
            if ! confirm_action "Continue anyway?" "N"; then
                return 1
            fi
        fi
        
        # Ask user how much of the disk to sample
        echo -e "${YELLOW}How much of the disk to sample:${NC}"
        echo -e "${CYAN}1.${NC} Quick check (first 10MB)"
        echo -e "${CYAN}2.${NC} Standard check (first 100MB)"
        echo -e "${CYAN}3.${NC} Thorough check (first 1GB)"
        echo -e "${CYAN}4.${NC} Custom sample size"
        
        read -p "$(echo -e "${YELLOW}Enter choice [1-4]:${NC} ")" check_level
        
        local block_count
        case $check_level in
            1) block_count=20480 ;; # 10MB (512-byte blocks)
            2) block_count=204800 ;; # 100MB
            3) block_count=2048000 ;; # 1GB
            4) 
                read -p "$(echo -e "${YELLOW}Enter sample size in MB:${NC} ")" custom_size
                if [[ "$custom_size" =~ ^[0-9]+$ ]]; then
                    block_count=$((custom_size * 2048)) # Convert MB to 512-byte blocks
                else
                    block_count=20480 # Default to 10MB if invalid
                    show_notification "Invalid size, using 10MB" "warning"
                fi
                ;;
            *) block_count=20480 ;; # Default to 10MB
        esac
        
        show_notification "Sampling $target_disk for non-zero data..." "info"
        
        # Offer different scanning methods
        echo -e "${YELLOW}Select scanning method:${NC}"
        echo -e "${CYAN}1.${NC} Basic zero detection (fast but basic)"
        echo -e "${CYAN}2.${NC} Pattern detection (slower but detects wiping patterns)"
        echo -e "${CYAN}3.${NC} String search (look for specific text in the disk)"
        
        read -p "$(echo -e "${YELLOW}Enter choice [1-3]:${NC} ")" scan_method
        
        case $scan_method in
            1)
                # Basic zero detection (original method)
                local temp_file=$(mktemp)
                local zero_blocks=0
                local total_blocks=0
                
                for ((i=0; i<block_count; i+=1024)); do
                    # Read 1024 blocks at a time
                    dd if=$target_disk of=$temp_file bs=512 skip=$i count=1024 conv=noerror status=none 2>/dev/null
                    
                    # Count zero blocks
                    local zeros=$(hexdump -v -e '/1 "%02X"' $temp_file | tr -d '00' | wc -c)
                    
                    if [ $zeros -eq 0 ]; then
                        zero_blocks=$((zero_blocks + 1024))
                    fi
                    
                    total_blocks=$((total_blocks + 1024))
                    
                    # Show progress
                    if [ $((i % 10240)) -eq 0 ]; then
                        show_progress $block_count $i "Sampling disk"
                    fi
                done
                
                # Clean up
                rm -f $temp_file
                
                # Calculate percentage of zero blocks
                local zero_percent=$((zero_blocks * 100 / total_blocks))
                
                echo -e "\n${YELLOW}Disk Wiping Analysis:${NC}"
                echo -e "${WHITE}Blocks sampled: $total_blocks${NC}"
                echo -e "${WHITE}Zero blocks found: $zero_blocks (${zero_percent}%)${NC}"
                
                if [ $zero_percent -gt 95 ]; then
                    echo -e "${GREEN}The sampled portion of $target_disk appears to be sufficiently wiped.${NC}"
                elif [ $zero_percent -gt 80 ]; then
                    echo -e "${YELLOW}The sampled portion of $target_disk is mostly wiped, but may contain some remnant data.${NC}"
                else
                    echo -e "${RED}The sampled portion of $target_disk contains significant amounts of data.${NC}"
                    echo -e "${RED}For secure wiping, consider using tools like 'shred' or 'wipe'.${NC}"
                fi
                ;;
                
            2)
                # Pattern detection
                show_notification "Scanning for wiping patterns..." "info"
                log_action "Checking for disk wiping patterns on $target_disk"
                
                local temp_file=$(mktemp)
                local patterns_found=()
                local pattern_counts=()
                
                # Common wiping patterns to check for
                local patterns=(
                    "000000" # Zeros
                    "ffffff" # Ones
                    "555555" # 01010101 pattern
                    "aaaaaa" # 10101010 pattern
                    "92492d" # RCMP TSSIT OPS-II pattern
                    "random" # Random data (special case)
                )
                
                # Initialize pattern counts
                for ((i=0; i<${#patterns[@]}; i++)); do
                    pattern_counts[$i]=0
                done
                
                # Sample the disk in multiple locations
                local sample_points=10
                local sample_size=2048 # 1MB per sample
                
                # Calculate step size to distribute samples across the device
                local dev_size=$(blockdev --getsize $target_disk 2>/dev/null)
                local step=$((dev_size / sample_points))
                
                if [ $step -lt $sample_size ]; then
                    sample_points=1
                    step=0
                fi
                
                for ((sp=0; sp<sample_points; sp++)); do
                    local offset=$((sp * step))
                    
                    # Show progress
                    show_progress $sample_points $sp "Analyzing patterns"
                    
                    # Read sample
                    dd if=$target_disk of=$temp_file bs=512 skip=$offset count=$sample_size conv=noerror status=none 2>/dev/null
                    
                    # Check for known patterns
                    for ((i=0; i<${#patterns[@]}; i++)); do
                        if [ "${patterns[$i]}" == "random" ]; then
                            # For random data, check entropy
                            local entropy=$(ent $temp_file 2>/dev/null | grep "Entropy" | awk '{print $3}')
                            
                            # If entropy is high, likely random data
                            if [ -n "$entropy" ] && (( $(echo "$entropy > 7.5" | bc -l) )); then
                                pattern_counts[$i]=$((pattern_counts[$i] + 1))
                            fi
                        else
                            # Check for repeating pattern
                            local hex_dump=$(hexdump -v -e '"%02x"' $temp_file | head -c 30000)
                            
                            # Look for repeating pattern
                            if echo "$hex_dump" | grep -q "${patterns[$i]}\{50,\}"; then
                                pattern_counts[$i]=$((pattern_counts[$i] + 1))
                            fi
                        fi
                    done
                done
                
                # Clean up
                rm -f $temp_file
                
                # Analyze results
                echo -e "\n${YELLOW}Disk Wiping Pattern Analysis:${NC}"
                
                local strongest_pattern_idx=0
                local strongest_pattern_count=0
                
                for ((i=0; i<${#patterns[@]}; i++)); do
                    local pattern_name=""
                    case "${patterns[$i]}" in
                        "000000") pattern_name="Zeros (Simplest wiping)" ;;
                        "ffffff") pattern_name="Ones" ;;
                        "555555") pattern_name="Alternating 01010101" ;;
                        "aaaaaa") pattern_name="Alternating 10101010" ;;
                        "92492d") pattern_name="RCMP TSSIT OPS-II" ;;
                        "random") pattern_name="Random data" ;;
                    esac
                    
                    local percentage=$((pattern_counts[$i] * 100 / sample_points))
                    echo -e "${WHITE}${pattern_name}: ${percentage}% of samples${NC}"
                    
                    if [ ${pattern_counts[$i]} -gt $strongest_pattern_count ]; then
                        strongest_pattern_count=${pattern_counts[$i]}
                        strongest_pattern_idx=$i
                    fi
                done
                
                echo ""
                
                # Give overall assessment
                if [ $strongest_pattern_count -gt $((sample_points / 2)) ]; then
                    local pattern_name=""
                    case "${patterns[$strongest_pattern_idx]}" in
                        "000000") pattern_name="zeros" ;;
                        "ffffff") pattern_name="ones" ;;
                        "555555") pattern_name="alternating bits (01010101)" ;;
                        "aaaaaa") pattern_name="alternating bits (10101010)" ;;
                        "92492d") pattern_name="RCMP TSSIT OPS-II secure wiping pattern" ;;
                        "random") pattern_name="random data" ;;
                    esac
                    
                    local confidence=$((strongest_pattern_count * 100 / sample_points))
                    echo -e "${GREEN}Evidence of disk wiping detected using ${pattern_name} (${confidence}% confidence).${NC}"
                    
                    if [ "${patterns[$strongest_pattern_idx]}" == "random" ] || [ "${patterns[$strongest_pattern_idx]}" == "92492d" ]; then
                        echo -e "${GREEN}This appears to be a secure wiping method.${NC}"
                    elif [ "${patterns[$strongest_pattern_idx]}" == "000000" ]; then
                        echo -e "${YELLOW}Basic zero-fill wiping detected. This is better than nothing but not forensically secure.${NC}"
                    else
                        echo -e "${YELLOW}Simple pattern wiping detected. This is better than nothing but not forensically secure.${NC}"
                    fi
                else
                    echo -e "${RED}No consistent wiping pattern detected. Disk may contain original data or mixed content.${NC}"
                fi
                ;;
                
            3)
                # String search
                show_notification "Searching for text strings in disk..." "info"
                log_action "Searching for text strings in $target_disk"
                
                # Create a temporary file for output
                local temp_file=$(mktemp)
                local strings_file=$(mktemp)
                
                # Use dd to sample the disk and strings to extract text
                echo -e "${YELLOW}Extracting strings from $target_disk...${NC}"
                dd if=$target_disk bs=512 count=$block_count | strings > $strings_file 2>/dev/null
                
                echo -e "${YELLOW}What kind of data would you like to search for?${NC}"
                echo -e "${CYAN}1.${NC} Personally identifiable information (names, emails, etc.)"
                echo -e "${CYAN}2.${NC} System files and paths"
                echo -e "${CYAN}3.${NC} Custom search string"
                
                read -p "$(echo -e "${YELLOW}Enter choice [1-3]:${NC} ")" string_choice
                
                local search_results=0
                
                case $string_choice in
                    1)
                        # Search for PII patterns
                        echo -e "${YELLOW}Searching for personally identifiable information...${NC}"
                        
                        # Email patterns
                        grep -E -i "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" $strings_file > $temp_file
                        local email_count=$(wc -l < $temp_file)
                        
                        # Show sample if found
                        if [ $email_count -gt 0 ]; then
                            echo -e "${RED}Found $email_count potential email addresses. Sample:${NC}"
                            head -n 5 $temp_file | while read line; do
                                echo -e "${WHITE}$line${NC}"
                            done
                            search_results=$((search_results + email_count))
                        else
                            echo -e "${GREEN}No email addresses found.${NC}"
                        fi
                        
                        # Phone number patterns (simple)
                        grep -E -i "(\+[0-9]{1,3}[ -]?)?(\([0-9]{3}\)|[0-9]{3})[ -]?[0-9]{3}[ -]?[0-9]{4}" $strings_file > $temp_file
                        local phone_count=$(wc -l < $temp_file)
                        
                        if [ $phone_count -gt 0 ]; then
                            echo -e "${RED}Found $phone_count potential phone numbers. Sample:${NC}"
                            head -n 5 $temp_file | while read line; do
                                echo -e "${WHITE}$line${NC}"
                            done
                            search_results=$((search_results + phone_count))
                        else
                            echo -e "${GREEN}No phone numbers found.${NC}"
                        fi
                        
                        # Names (common first/last name patterns)
                        grep -E -i "Mr\.|Mrs\.|Ms\.|Dr\.|Prof\." $strings_file | grep -E -i "[A-Z][a-z]+" > $temp_file
                        local name_count=$(wc -l < $temp_file)
                        
                        if [ $name_count -gt 0 ]; then
                            echo -e "${RED}Found $name_count potential name references. Sample:${NC}"
                            head -n 5 $temp_file | while read line; do
                                echo -e "${WHITE}$line${NC}"
                            done
                            search_results=$((search_results + name_count))
                        else
                            echo -e "${GREEN}No name references found.${NC}"
                        fi
                        ;;
                        
                    2)
                        # Search for system files and paths
                        echo -e "${YELLOW}Searching for system files and paths...${NC}"
                        
                        # Common Linux paths
                        grep -E -i "/(bin|etc|home|usr|var|opt|tmp)/" $strings_file > $temp_file
                        local path_count=$(wc -l < $temp_file)
                        
                        if [ $path_count -gt 0 ]; then
                            echo -e "${RED}Found $path_count potential filesystem paths. Sample:${NC}"
                            head -n 5 $temp_file | while read line; do
                                echo -e "${WHITE}$line${NC}"
                            done
                            search_results=$((search_results + path_count))
                        else
                            echo -e "${GREEN}No filesystem paths found.${NC}"
                        fi
                        
                        # Common file extensions
                        grep -E -i "\.(conf|log|xml|json|txt|sh|py|pl|rb|php|html|js|css|jpg|png|pdf|doc|xls|ppt)(\s|$)" $strings_file > $temp_file
                        local ext_count=$(wc -l < $temp_file)
                        
                        if [ $ext_count -gt 0 ]; then
                            echo -e "${RED}Found $ext_count potential filenames. Sample:${NC}"
                            head -n 5 $temp_file | while read line; do
                                echo -e "${WHITE}$line${NC}"
                            done
                            search_results=$((search_results + ext_count))
                        else
                            echo -e "${GREEN}No filenames found.${NC}"
                        fi
                        ;;
                        
                    3)
                        # Custom search string
                        read -p "$(echo -e "${YELLOW}Enter custom search term:${NC} ")" search_term
                        
                        if [ -n "$search_term" ]; then
                            echo -e "${YELLOW}Searching for \"$search_term\"...${NC}"
                            
                            # Do the search
                            grep -i "$search_term" $strings_file > $temp_file
                            local custom_count=$(wc -l < $temp_file)
                            
                            if [ $custom_count -gt 0 ]; then
                                echo -e "${RED}Found $custom_count matches for \"$search_term\". Sample:${NC}"
                                head -n 10 $temp_file | while read line; do
                                    echo -e "${WHITE}$line${NC}"
                                done
                                search_results=$((search_results + custom_count))
                            else
                                echo -e "${GREEN}No matches found for \"$search_term\".${NC}"
                            fi
                        else
                            show_notification "No search term provided" "warning"
                        fi
                        ;;
                esac
                
                # Give overall assessment based on string search
                echo -e "\n${YELLOW}String Search Analysis:${NC}"
                if [ $search_results -eq 0 ]; then
                    echo -e "${GREEN}No sensitive strings found. The sampled portion of the disk appears to be wiped.${NC}"
                elif [ $search_results -lt 10 ]; then
                    echo -e "${YELLOW}A few strings found ($search_results). The disk may be partially wiped or contain minimal data.${NC}"
                else
                    echo -e "${RED}Multiple strings found ($search_results). The disk appears to contain recoverable data.${NC}"
                    echo -e "${RED}For secure wiping, consider using tools like 'shred' or 'wipe'.${NC}"
                fi
                
                # Clean up
                rm -f $temp_file $strings_file
                ;;
        esac
        
        log_action "Completed disk wiping verification on $target_disk"
        
        # Offer secure wiping if recoverable data was found
        if [ $scan_method -eq 1 ] && [ $zero_percent -lt 80 ] || 
           [ $scan_method -eq 2 ] && [ $strongest_pattern_count -le $((sample_points / 2)) ] || 
           [ $scan_method -eq 3 ] && [ $search_results -gt 10 ]; then
            
            # Prompt for the disk to wipe
            if confirm_action "Would you like to securely wipe this disk now?" "N"; then
                # Extra safety checks
                show_notification "⚠️ ⚠️ ⚠️ CRITICAL WARNING ⚠️ ⚠️ ⚠️" "error"
                show_notification "Disk wiping will PERMANENTLY DESTROY ALL DATA on the target disk!" "error"
                echo -e "${RED}This operation will:"
                echo -e "  • Permanently erase ALL data on the disk"
                echo -e "  • Make data recovery impossible even by professional services"
                echo -e "  • Potentially render your system unbootable if system disk is selected"
                echo -e "  • Cannot be undone or interrupted safely once started${NC}"
                
                # Get the list of mounted disks to warn about system disks
                local mounted_disks=$(mount | grep "^/dev/" | awk '{print $1}' | sort | uniq)
                if echo "$mounted_disks" | grep -q "$target_disk"; then
                    show_notification "WARNING: $target_disk is currently mounted and may be a system disk!" "error"
                    show_notification "Wiping a system disk will make your system UNUSABLE!" "error"
                    
                    # Immediate abort for root partitions
                    if mount | grep "on / " | grep -q "$target_disk"; then
                        show_notification "CRITICAL SAFETY ABORT: Cannot wipe root partition!" "error"
                        log_action "Disk wipe aborted: Attempted to wipe root partition"
                        return 1
                    fi
                fi
                
                # Get size of disk for additional warning
                local disk_size=$(lsblk -dno SIZE "$target_disk" 2>/dev/null || echo "Unknown")
                show_notification "Disk size: $disk_size" "warning"
                
                # Show connected devices
                echo -e "${YELLOW}Currently connected disks:${NC}"
                lsblk -o NAME,SIZE,TYPE,MOUNTPOINT | grep -v "loop" | grep "disk"
                
                # Multiple confirmations
                if ! confirm_action "Are you absolutely sure you want to wipe $target_disk? This cannot be undone." "N"; then
                    show_notification "Disk wiping aborted by user" "info"
                    log_action "Disk wiping aborted by user: $target_disk"
                    return 1
                fi
                
                # Get disk identifier from blkid
                local disk_info=$(blkid "$target_disk" 2>/dev/null || echo "Unknown")
                log_action "Disk information before wiping: $disk_info"
                
                # Final verification with a random code
                local verification_code=$(tr -dc 'A-Z0-9' < /dev/urandom | head -c 8)
                echo -e "${RED}FINAL VERIFICATION REQUIRED${NC}"
                echo -e "To confirm deletion of ALL DATA on ${RED}$target_disk ($disk_size)${NC}, type this code:"
                echo -e "${YELLOW}$verification_code${NC}"
                read -p "Verification code: " user_code
                
                if [ "$user_code" != "$verification_code" ]; then
                    show_notification "Incorrect verification code. Disk wiping aborted." "info"
                    log_action "Disk wiping aborted: incorrect verification code for $target_disk"
                    return 1
                fi
                
                # Create a timestamp for the operation
                local timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
                log_action "Starting disk wipe of $target_disk at $timestamp"
                
                # Check if disk is mounted and try to unmount
                if mount | grep -q "$target_disk"; then
                    show_notification "Attempting to unmount $target_disk..." "info"
                    umount "$target_disk"* 2>/dev/null
                    if mount | grep -q "$target_disk"; then
                        show_notification "Failed to unmount $target_disk. Cannot proceed." "error"
                        log_action "Disk wiping failed: Unable to unmount $target_disk"
                        return 1
                    fi
                fi
                
                # Choose wiping method
                echo -e "${YELLOW}Select wiping method:${NC}"
                echo -e "${CYAN}1.${NC} Zero-fill (fast but not forensically secure)"
                echo -e "${CYAN}2.${NC} Single random pass (more secure)"
                echo -e "${CYAN}3.${NC} 3-pass DoD method (secure, slow)"
                echo -e "${CYAN}4.${NC} 7-pass method (very secure, very slow)"
                
                read -p "$(echo -e "${YELLOW}Enter choice [1-4]:${NC} ")" wipe_choice
                
                case $wipe_choice in
                    1)
                        # Zero-fill
                        show_notification "Starting zero-fill wipe of $target_disk..." "info"
                        log_action "Starting zero-fill wipe of $target_disk"
                        
                        dd if=/dev/zero of=$target_disk bs=4M conv=noerror status=progress
                        
                        log_action "Completed zero-fill wipe of $target_disk"
                        show_notification "Zero-fill wipe completed" "success"
                        ;;
                    2)
                        # Single random pass
                        show_notification "Starting random data wipe of $target_disk..." "info"
                        log_action "Starting random data wipe of $target_disk"
                        
                        dd if=/dev/urandom of=$target_disk bs=4M conv=noerror status=progress
                        
                        log_action "Completed random data wipe of $target_disk"
                        show_notification "Random data wipe completed" "success"
                        ;;
                    3)
                        # 3-pass DoD method
                        show_notification "Starting 3-pass DoD wipe of $target_disk..." "info"
                        log_action "Starting 3-pass DoD wipe of $target_disk"
                        
                        if command_exists shred; then
                            shred -v -n 3 -z $target_disk
                        else
                            show_notification "shred command not found, using manual method" "warning"
                            
                            # Pass 1: Zeros
                            show_notification "Pass 1/3: Zero fill..." "info"
                            dd if=/dev/zero of=$target_disk bs=4M conv=noerror status=progress
                            
                            # Pass 2: Random
                            show_notification "Pass 2/3: Random data..." "info"
                            dd if=/dev/urandom of=$target_disk bs=4M conv=noerror status=progress
                            
                            # Pass 3: Zeros again
                            show_notification "Pass 3/3: Zero fill..." "info"
                            dd if=/dev/zero of=$target_disk bs=4M conv=noerror status=progress
                        fi
                        
                        log_action "Completed 3-pass DoD wipe of $target_disk"
                        show_notification "3-pass DoD wipe completed" "success"
                        ;;
                    4)
                        # 7-pass method
                        show_notification "Starting 7-pass wipe of $target_disk..." "info"
                        log_action "Starting 7-pass wipe of $target_disk"
                        
                        if command_exists shred; then
                            shred -v -n 7 -z $target_disk
                        else
                            show_notification "shred command not found, using manual method (this will take a very long time)" "warning"
                            
                            # 7 passes with different patterns
                            patterns=("/dev/zero" "/dev/urandom" "/dev/zero" "/dev/urandom" "/dev/zero" "/dev/urandom" "/dev/zero")
                            
                            for ((i=0; i<7; i++)); do
                                show_notification "Pass $((i+1))/7: $([ ${patterns[$i]} == '/dev/zero' ] && echo 'Zero fill' || echo 'Random data')..." "info"
                                dd if=${patterns[$i]} of=$target_disk bs=4M conv=noerror status=progress
                            done
                        fi
                        
                        log_action "Completed 7-pass wipe of $target_disk"
                        show_notification "7-pass wipe completed" "success"
                        ;;
                    *)
                        show_notification "Invalid choice, wiping cancelled" "error"
                        ;;
                esac
            fi
        fi
        
        echo ""
        read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
    fi
    
    return 0
}

# Function to handle hardware cleaning operations
handle_hardware_cleaning() {
    clear
    display_section_header "Hardware-Level Trace Elimination"
    
    local options=(
        "Clean Firmware Logs (UEFI/BIOS)"
        "Clean Device Firmware Logs"
        "Check for Hardware Keyloggers"
        "Clean Network Hardware Traces"
        "Verify Disk Wiping"
        "Return to Main Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" choice

    case $choice in
        1) 
            clean_firmware_logs
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_hardware_cleaning
            ;;
        2) 
            clean_device_firmware
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_hardware_cleaning
            ;;
        3) 
            check_hardware_keyloggers
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_hardware_cleaning
            ;;
        4) 
            clean_network_hardware
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_hardware_cleaning
            ;;
        5) 
            verify_disk_wiping
            echo ""
            read -p "$(echo -e "${GREEN}Press Enter to continue...${NC}")"
            handle_hardware_cleaning
            ;;
        6) return 0 ;;
        *)
            show_notification "Invalid option" "error"
            sleep 1
            handle_hardware_cleaning
            ;;
    esac
}