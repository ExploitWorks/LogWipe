#!/bin/bash

# LogWipe - A comprehensive log management tool for Linux systems
# Author: Jonas Resch
# Version: 1.0

# Configuration
CONFIG_DIR="config"
CONFIG_FILE="$CONFIG_DIR/logwipe.conf"
LOG_DIR="logs"
LOG_FILE="$LOG_DIR/logwipe.log"

# Source modules
echo "Initializing LogWipe..."

# Create necessary directories
mkdir -p "$CONFIG_DIR" "$LOG_DIR"

# First load the UI utilities
if [ -f "src/utils/ui.sh" ]; then
    source src/utils/ui.sh
else
    echo "Error: UI utilities not found."
    exit 1
fi

# Display initial loading animation
animate_text "Loading modules..." 0.05

# Function to source a module with error handling
load_module() {
    local module="$1"
    if [ -f "$module" ]; then
        source "$module" && show_notification "Loaded $module" "success"
    else
        show_notification "Error: Module not found: $module" "error"
        return 1
    fi
    return 0
}

# Load core modules
load_module "src/utils/helpers.sh" || exit 1
load_module "src/modules/log_cleaner.sh" || exit 1
load_module "src/modules/fake_logger.sh" || exit 1
load_module "src/modules/system_analyzer.sh" || exit 1
load_module "src/modules/anti_forensics.sh" || exit 1
load_module "src/modules/deep_cleaner.sh" || exit 1
load_module "src/modules/kernel_cleaner.sh" || exit 1
load_module "src/modules/hardware_cleaner.sh" || exit 1
load_module "src/modules/attribution_cleaner.sh" || exit 1

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    show_notification "Please run as root" "error"
    exit 1
fi

# Initialize log file
init_logging

# Load configuration
if [ -f "$CONFIG_FILE" ]; then
    parse_config "$CONFIG_FILE"
    log_action "Loaded configuration file: $CONFIG_FILE"
else
    log_action "Configuration file not found: $CONFIG_FILE"
    create_sample_config "$CONFIG_FILE"
    show_notification "Created default configuration file: $CONFIG_FILE" "warning"
    parse_config "$CONFIG_FILE" # Load defaults created
fi

# Validate log paths in the configuration
validate_log_paths

# Initialize verbose mode from config
verbose=${VERBOSE_MODE:-false}

# Set default security level if not defined in config
SECURITY_LEVEL=${SECURITY_LEVEL:-"standard"}

# Propagate the verbose setting to all modules
propagate_verbose_setting() {
    # We've already initialized verbose based on VERBOSE_MODE
    # This function ensures that any changes to verbose (via toggle) are saved to config
    if [ "$VERBOSE_MODE" != "$verbose" ]; then
        VERBOSE_MODE="$verbose"
        
        # Update the config file
        if [ -f "$CONFIG_FILE" ]; then
            sed -i "s/^VERBOSE_MODE=.*/VERBOSE_MODE=$verbose/" "$CONFIG_FILE"
            log_action "Updated VERBOSE_MODE in config to $verbose"
        fi
    fi
}

# Function to toggle verbose mode (original implementation in log_cleaner.sh)
toggle_verbose_mode() {
    if [ "$verbose" = true ]; then
        verbose=false
        show_notification "Verbose mode disabled" "warning"
    else
        verbose=true
        show_notification "Verbose mode enabled" "success"
    fi
    
    # Propagate changes to config
    propagate_verbose_setting
    
    sleep 1
}

# Function to handle log cleaning operations
handle_log_cleaning() {
    clear
    display_section_header "Log Cleaning Options"
    
    local options=(
        "Clean All Logs (Complete Wipe)"
        "Clean System Logs Only"
        "Clean User Logs Only"
        "Clean Application Logs Only"
        "Clean Network Traces Only"
        "Custom Cleaning (Select Specific Logs)"
        "Return to Main Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" clean_choice

    case $clean_choice in
        1) 
            animate_text "Preparing to clean all logs based on Security Level: $SECURITY_LEVEL..." 0.03
            show_notification "Running initial log cleaning..." "info"
            clean_logs "all" # Basic cleaning first
            
            if [ "$SECURITY_LEVEL" = "enhanced" ] || [ "$SECURITY_LEVEL" = "maximum" ]; then
                show_notification "Running Attribution Cleaning (Enhanced Level)..." "info"
                clean_timing_patterns
                clean_geo_traces
                clean_writing_patterns
                clean_keyboard_patterns
                clean_tool_patterns
                clean_malware_signatures
            fi
            
            if [ "$SECURITY_LEVEL" = "maximum" ]; then
                show_notification "Running Deep Cleaning (Maximum Level)..." "info"
                clean_memory_artifacts
                clean_process_history
                clean_temps_and_caches
                clean_filesystem_traces
                clean_network_traces
                clean_application_traces
                clean_audit_traces
                clean_container_traces
                
                show_notification "Running Kernel Cleaning (Maximum Level)..." "info"
                clear_kernel_messages
                clean_kernel_modules
                clear_sysrq_traces
                clean_packet_traces
                clear_kernel_accounting
                clean_kernel_crash_dumps
                # Skip timestamp manipulation as it's high risk
                clean_systemd_journal
            fi
            show_notification "Comprehensive cleaning based on Security Level '$SECURITY_LEVEL' completed." "success"
            sleep 2
            ;;
        2) 
            animate_text "Preparing to clean system logs..." 0.03
            clean_logs "system"
            ;;
        3) 
            animate_text "Preparing to clean user logs..." 0.03
            clean_logs "user"
            ;;
        4) 
            animate_text "Preparing to clean application logs..." 0.03
            clean_logs "application"
            ;;
        5) 
            animate_text "Preparing to clean network traces..." 0.03
            clean_logs "network"
            ;;
        6) custom_log_cleaning ;;
        7) return 0 ;;
        *) 
            show_notification "Invalid option" "error"
            sleep 1
            handle_log_cleaning
            ;;
    esac
}

# Function to handle fake log generation
handle_fake_logs() {
    clear
    display_section_header "Fake Log Generation Options"
    
    local options=(
        "Generate All Types of Logs"
        "Generate System Logs Only"
        "Generate Auth Logs Only"
        "Generate Web Server Logs Only"
        "Generate Database Logs Only"
        "Generate Custom Scenario Logs"
        "Configure Log Generation Settings"
        "Return to Main Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" fake_choice

    case $fake_choice in
        1) 
            animate_text "Preparing to generate all types of logs..." 0.03
            generate_fake_logs "all"
            ;;
        2) 
            animate_text "Preparing to generate system logs..." 0.03
            generate_fake_logs "system"
            ;;
        3) 
            animate_text "Preparing to generate auth logs..." 0.03
            generate_fake_logs "auth"
            ;;
        4) 
            animate_text "Preparing to generate web logs..." 0.03
            generate_fake_logs "web"
            ;;
        5) 
            animate_text "Preparing to generate database logs..." 0.03
            generate_fake_logs "database"
            ;;
        6) custom_fake_logs ;;
        7) set_generation_preferences ;;
        8) return 0 ;;
        *) 
            show_notification "Invalid option" "error"
            sleep 1
            handle_fake_logs
            ;;
    esac
}

# Function to handle system analysis
handle_system_analysis() {
    clear
    display_section_header "System Analysis"
    
    local options=(
        "Full System Log Analysis"
        "Security Audit"
        "Log Size Analysis"
        "Activity Timeline"
        "Return to Main Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" analysis_choice

    case $analysis_choice in
        1)
            animate_text "Analyzing system logs..." 0.03
            analyze_system_logs
            ;;
        2)
            animate_text "Performing security audit..." 0.03
            security_audit
            ;;
        3)
            animate_text "Analyzing log sizes..." 0.03
            analyze_log_sizes
            ;;
        4)
            animate_text "Generating activity timeline..." 0.03
            generate_timeline
            ;;
        5) return 0 ;;
        *) 
            show_notification "Invalid option" "error"
            sleep 1
            handle_system_analysis
            ;;
    esac
}

# Function to handle anti-forensics operations
handle_anti_forensics_menu() {
    # Call the anti-forensics module function
    handle_anti_forensics
}

# Main menu with improved UI
show_menu() {
    clear
    display_banner
    
    local options=(
        "Clean Logs"
        "Generate Fake Logs"
        "System Analysis"
        "Anti-Forensics Operations"
        "Advanced Trace Elimination"
        "Kernel-Level Trace Elimination"
        "Hardware-Level Trace Elimination"
        "Behavioral & Attribution Trace Elimination"
        "${RED}Self-Destruct (Remove All Traces)${NC}"
        "Settings"
        "Exit"
    )
    
    display_menu "Main Menu" "${options[@]}"
    display_footer
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" choice

    case $choice in
        1) 
            handle_log_cleaning
            show_menu
            ;;
        2) 
            handle_fake_logs
            show_menu
            ;;
        3) 
            handle_system_analysis
            show_menu
            ;;
        4) 
            if [ "$SECURITY_LEVEL" = "standard" ]; then
                show_notification "Warning: Security Level is Standard. Anti-Forensics may require Enhanced or Maximum for full effect." "warning"
                sleep 1
            fi
            handle_anti_forensics_menu 
            show_menu
            ;;
        5) 
            if [ "$SECURITY_LEVEL" != "maximum" ]; then
                show_notification "Warning: Security Level is not Maximum. Advanced Trace Elimination is designed for Maximum level." "warning"
                sleep 1
            fi
            handle_deep_cleaning 
            show_menu
            ;;
        6) 
            if [ "$SECURITY_LEVEL" != "maximum" ]; then
                show_notification "Warning: Security Level is not Maximum. Kernel Cleaning is designed for Maximum level." "warning"
                sleep 1
            fi
            handle_kernel_cleaning 
            show_menu
            ;;
        7)
            if [ "$SECURITY_LEVEL" = "standard" ]; then
                show_notification "Warning: Some Hardware Cleaning features may require Enhanced or Maximum level." "warning"
                sleep 1
            fi
            handle_hardware_cleaning 
            show_menu
            ;;
        8) 
            if [ "$SECURITY_LEVEL" = "standard" ]; then
                show_notification "Warning: Security Level is Standard. Attribution Cleaning may require Enhanced or Maximum for full effect." "warning"
                sleep 1
            fi
            handle_attribution_cleaning 
            show_menu
            ;;
        9) 
            # Show a clear warning about self-destruct
            clear
            echo -e "${RED}╔════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}║               WARNING: SELF-DESTRUCT                   ║${NC}"
            echo -e "${RED}║                                                        ║${NC}"
            echo -e "${RED}║  This will permanently remove ALL traces of LogWipe    ║${NC}"
            echo -e "${RED}║  from your system, including the application itself.   ║${NC}"
            echo -e "${RED}║                                                        ║${NC}"
            echo -e "${RED}║  The process is IRREVERSIBLE once confirmed.           ║${NC}"
            echo -e "${RED}╚════════════════════════════════════════════════════════╝${NC}"
            echo ""
            
            if confirm_action "Initiate self-destruct sequence?" "N"; then
                # Run the self-destruct function
                self_destruct
            else
                show_notification "Self-destruct aborted" "info"
            fi
            
            # If we return from self-destruct (user canceled), go back to menu
            show_menu
            ;;
        10) 
            show_settings
            ;;
        11) 
            clear
            animate_text "Thank you for using LogWipe!" 0.05 "$GREEN"
            exit 0
            ;;
        *)
            show_notification "Invalid option" "error"
            sleep 1
            show_menu
            ;;
    esac
}

# Settings menu
show_settings() {
    clear
    display_section_header "Settings"
    
    local options=(
        "Set Security Level"
        "Toggle Verbose Mode ($([ "$verbose" = true ] && echo "Enabled" || echo "Disabled"))"
        "View System Information"
        "Check System Requirements"
        "Return to Main Menu"
    )
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Select an option:${NC} ")" settings_choice

    case $settings_choice in
        1) 
            configure_security_level 
            show_settings
            ;;
        2) 
            toggle_verbose_mode 
            show_settings
            ;;
        3) 
            get_system_info 
            show_settings
            ;;
        4) 
            check_requirements 
            show_settings
            ;;
        5) return 0 ;;
        *) 
            show_notification "Invalid option" "error"
            sleep 1
            show_settings
            ;;
    esac
}

# Function to configure security level
configure_security_level() {
    clear
    display_section_header "Security Level Configuration"
    
    echo -e "${YELLOW}Select security level:${NC}"
    echo -e "${CYAN}1.${NC} Standard (Basic log cleaning)"
    echo -e "${CYAN}2.${NC} Enhanced (Advanced cleaning with timestamp manipulation)"
    echo -e "${CYAN}3.${NC} Maximum (Full anti-forensics capabilities)"
    
    echo -e "${PURPLE}=========================================${NC}"
    read -p "$(echo -e "${YELLOW}Enter your selection [1-3]:${NC} ")" sec_level
    
    case $sec_level in
        1)
            SECURITY_LEVEL="standard"
            show_notification "Security level set to Standard" "info"
            ;;
        2)
            SECURITY_LEVEL="enhanced"
            show_notification "Security level set to Enhanced" "info"
            ;;
        3)
            SECURITY_LEVEL="maximum"
            show_notification "Security level set to Maximum" "warning"
            show_notification "Warning: Use Maximum level with caution" "warning"
            ;;
        *)
            show_notification "Invalid option, using Standard level" "error"
            SECURITY_LEVEL="standard"
            ;;
    esac
    
    # Save to config file
    if [ -f "$CONFIG_FILE" ]; then
        # Check if SECURITY_LEVEL already exists in the config
        if grep -q "^SECURITY_LEVEL=" "$CONFIG_FILE"; then
            # Update the existing line
            sed -i "s/^SECURITY_LEVEL=.*/SECURITY_LEVEL=\"$SECURITY_LEVEL\"/" "$CONFIG_FILE"
        else
            # Add a new line
            echo "SECURITY_LEVEL=\"$SECURITY_LEVEL\"" >> "$CONFIG_FILE"
        fi
    fi
    
    log_action "Set security level to $SECURITY_LEVEL"
    sleep 1
    return 0
}

# Splash screen
clear
display_banner
animate_text "Welcome to LogWipe - Advanced Log Management Tool" 0.03
animate_text "Loading..." 0.1

# Check system requirements
if ! check_requirements; then
    if confirm_action "Some requirements are not met. Continue anyway?" "N"; then
        show_notification "Continuing with limited functionality" "warning"
    else
        show_notification "Exiting due to unmet requirements" "error"
        exit 1
    fi
fi

# Start the application
show_notification "LogWipe initialized successfully" "success"
sleep 1
show_menu 