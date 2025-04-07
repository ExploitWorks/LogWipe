#!/bin/bash

# UI utilities for LogWipe

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
NC='\033[0m' # No Color

# Function to display application banner
display_banner() {
    echo -e "${BLUE}"
    echo " _                 _    _ _            "
    echo "| |               | |  | (_)           "
    echo "| |     ___   __ _| |  | |_ _ __   ___ "
    echo "| |    / _ \\ / _\` | |/\\| | | '_ \\ / _ \\"
    echo "| |___| (_) | (_| \\  /\\  / | |_) |  __/"
    echo "\\_____/\\___/ \\__, |\\/  \\/|_| .__/ \\___|"
    echo "              __/ |        | |         "
    echo -e "             |___/         |_|   ${WHITE}v1.0${BLUE}  "
    echo -e "${NC}"
    echo -e "  ${BOLD}Advanced Log Management Tool for Linux Systems${NC}"
    echo -e "  ${CYAN}Developed by Jonas${NC}"
    echo ""
}

# Function to initialize logging
init_logging() {
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Initialize log file with header
    echo "# LogWipe Activity Log" > "$LOG_FILE"
    echo "# Started: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    echo "# User: $(whoami)" >> "$LOG_FILE"
    echo "# System: $(uname -a)" >> "$LOG_FILE"
    echo "---------------------------------" >> "$LOG_FILE"
}

# Function to log actions
log_action() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$LOG_FILE"
}

# Function to display a progress bar
show_progress() {
    local total="$1"
    local current="$2"
    local title="$3"
    local bar_length=50
    local progress=$((current * bar_length / total))
    local percentage=$((current * 100 / total))
    
    # Create the progress bar
    local bar=""
    for ((i=0; i<bar_length; i++)); do
        if [ $i -lt $progress ]; then
            bar="${bar}█"
        else
            bar="${bar}░"
        fi
    done
    
    # Display the progress bar with colors
    printf "\r${CYAN}%s ${GREEN}[%s] ${YELLOW}%d%%${NC}" "$title" "$bar" "$percentage"
    
    # If complete, move to the next line
    if [ $current -eq $total ]; then
        echo ""
    fi
}

# Function to show a confirmation dialog
confirm_action() {
    local message="$1"
    local default="$2"
    
    local prompt
    if [ "$default" = "Y" ]; then
        prompt="${message} ${GREEN}[Y/n]${NC}: "
    else
        prompt="${message} ${YELLOW}[y/N]${NC}: "
    fi
    
    read -p "$(echo -e "$prompt")" response
    
    if [ -z "$response" ]; then
        response="$default"
    fi
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to get operating system info
get_os_info() {
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        echo "$NAME $VERSION_ID"
    else
        uname -s
    fi
}

# Function to animate text
animate_text() {
    local text="$1"
    local delay="${2:-0.1}"
    local color="${3:-$CYAN}"
    
    echo -ne "$color"
    for ((i=0; i<${#text}; i++)); do
        printf "%s" "${text:$i:1}"
        sleep $delay
    done
    echo -e "$NC"
}

# Function to display section header
display_section_header() {
    local title="$1"
    local width=41
    local padding=$(( (width - ${#title}) / 2 ))
    
    echo -e "${PURPLE}=========================================${NC}"
    printf "${BOLD}${YELLOW}%*s%s%*s${NC}\n" $padding "" "$title" $padding ""
    echo -e "${PURPLE}=========================================${NC}"
}

# Function to display a menu
display_menu() {
    local title="$1"
    shift
    local options=("$@")
    
    display_section_header "$title"
    
    for i in "${!options[@]}"; do
        echo -e "${CYAN}$((i+1))${NC}. ${options[$i]}"
    done
    
    echo -e "${PURPLE}=========================================${NC}"
}

# Function to show a notification
show_notification() {
    local message="$1"
    local type="${2:-info}" # info, success, warning, error
    
    case "$type" in
        success)
            echo -e "${GREEN}✓ ${message}${NC}"
            ;;
        warning)
            echo -e "${YELLOW}⚠ ${message}${NC}"
            ;;
        error)
            echo -e "${RED}✖ ${message}${NC}"
            ;;
        *)
            echo -e "${BLUE}ℹ ${message}${NC}"
            ;;
    esac
}

# Function to get user input with validation
get_input() {
    local prompt="$1"
    local validation_regex="$2"
    local default="$3"
    local error_message="${4:-Invalid input, please try again.}"
    local input=""
    
    while true; do
        if [ -n "$default" ]; then
            echo -e "${CYAN}$prompt ${YELLOW}[$default]${NC}: "
        else
            echo -e "${CYAN}$prompt${NC}: "
        fi
        
        read input
        
        if [ -z "$input" ] && [ -n "$default" ]; then
            input="$default"
        fi
        
        if [[ -z "$validation_regex" ]] || [[ "$input" =~ $validation_regex ]]; then
            break
        else
            echo -e "${RED}$error_message${NC}"
        fi
    done
    
    echo "$input"
}

# Function to display a table
display_table() {
    local header=("$1")
    shift
    local rows=("$@")
    local column_widths=()
    
    # Calculate column widths
    IFS='|' read -ra header_cols <<< "$header"
    for col in "${header_cols[@]}"; do
        column_widths+=(${#col})
    done
    
    for row in "${rows[@]}"; do
        IFS='|' read -ra row_cols <<< "$row"
        for i in "${!row_cols[@]}"; do
            if [ ${#row_cols[$i]} -gt ${column_widths[$i]} ]; then
                column_widths[$i]=${#row_cols[$i]}
            fi
        done
    done
    
    # Print header
    echo -e "${PURPLE}-$(printf '%0.s-' $(seq 1 $((${#column_widths[@]} * 3 + $(IFS=+; echo "${column_widths[*]}")))))-${NC}"
    
    printf "${BOLD}${WHITE}"
    IFS='|' read -ra header_cols <<< "$header"
    for i in "${!header_cols[@]}"; do
        printf "| %-${column_widths[$i]}s " "${header_cols[$i]}"
    done
    printf "|${NC}\n"
    
    echo -e "${PURPLE}-$(printf '%0.s-' $(seq 1 $((${#column_widths[@]} * 3 + $(IFS=+; echo "${column_widths[*]}")))))-${NC}"
    
    # Print rows
    for row in "${rows[@]}"; do
        IFS='|' read -ra row_cols <<< "$row"
        for i in "${!row_cols[@]}"; do
            printf "${CYAN}| ${NC}%-${column_widths[$i]}s " "${row_cols[$i]}"
        done
        printf "|\n"
    done
    
    echo -e "${PURPLE}-$(printf '%0.s-' $(seq 1 $((${#column_widths[@]} * 3 + $(IFS=+; echo "${column_widths[*]}")))))-${NC}"
}

# Function to display the application footer
display_footer() {
    local os_info=$(get_os_info)
    local user=$(whoami)
    local date=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "${PURPLE}=========================================${NC}"
    echo -e "${BLUE}System: ${WHITE}$os_info${NC} | ${BLUE}User: ${WHITE}$user${NC} | ${BLUE}Date: ${WHITE}$date${NC}"
    echo -e "${PURPLE}=========================================${NC}"
} 