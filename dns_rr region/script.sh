#!/bin/bash

# RR Monitoring Script - Auto-detect and log timing when proxy calls
# Run this script ON THE RR PC before running client tests

# Configuration
RR_LOG_FILE="rr_monitor_$(date +%Y%m%d_%H%M%S).log"
TEMP_LOG="/tmp/rr_output.log"
RR_SCRIPT="2l_rr.py"  # Replace with your actual RR script name
MONITOR_DURATION=3600  # Monitor for 1 hour (adjust as needed)

# Function to clear local DNS cache and PowerDNS cache
clear_local_cache() {
    echo "Clearing RR DNS cache..."
    sudo rec_control wipe-cache . 2>/dev/null
    sudo resolvectl flush-caches 2>/dev/null
    sudo systemctl restart systemd-resolved 2>/dev/null
    sleep 1
}

# Function to process complete request data
process_request_data() {
    local request_data="$1"
    local run_number="$2"
    
    # Extract timestamps from this specific request - using corrected TIMESTAMP patterns
    local tw6=$(echo "$request_data" | grep "TIMESTAMP.*TW6 RR RECEIVES THE PACKET FROM PROXY" | awk '{print $2}')
    local tw7=$(echo "$request_data" | grep "TIMESTAMP.*TW7 BEGINS DECRYPTION FROM PROXY" | awk '{print $2}')
    local tw8=$(echo "$request_data" | grep "TIMESTAMP.*TW8 ENDS DECRYPTION FROM PROXY" | awk '{print $2}')
    local tw9=$(echo "$request_data" | grep "TIMESTAMP.*TW9 SENDS IT TO GLOBAL DNS" | awk '{print $2}')
    local tw10=$(echo "$request_data" | grep "TIMESTAMP.*TW10 SENDS IT TO CUSTOM DNS" | awk '{print $2}')
    local tw11=$(echo "$request_data" | grep "TIMESTAMP.*TW11 RECEIVES THE GLOBAL DNS RESULT" | awk '{print $2}')
    local tw19=$(echo "$request_data" | grep "TIMESTAMP.*TW19 RECEIVES CUSTOM DNS RESULT" | awk '{print $2}')
    local tw20=$(echo "$request_data" | grep "TIMESTAMP.*TW20 STARTS DECRYPTION FROM ANS" | awk '{print $2}')
    local tw21=$(echo "$request_data" | grep "TIMESTAMP.*TW21 ENDS DECRYPTION FROM ANS" | awk '{print $2}')
    local tw22=$(echo "$request_data" | grep "TIMESTAMP.*TW22 STARTS ENCRYPTING FOR PROXY" | awk '{print $2}')
    local tw23=$(echo "$request_data" | grep "TIMESTAMP.*TW23 ENDS ENCRYPTION FOR PROXY" | awk '{print $2}')
    local tw24=$(echo "$request_data" | grep "TIMESTAMP.*TW24 SENDS PACKET TO PROXY" | awk '{print $2}')
    local rr_rtt=$(echo "$request_data" | grep "RR RTT:" | awk '{print $3}' | sed 's/ms//')
    
    # Extract domain from "Checking domain:" line - fix the extraction
    local domain=$(echo "$request_data" | grep "Checking domain:" | awk '{print $3}' | sed 's/\.$//')
    
    # If domain extraction fails, try to extract from hex patterns for different domains
    if [ -z "$domain" ] || [ "$domain" = "" ]; then
        # Check for different domain hex patterns
        if echo "$request_data" | grep -q "676f6f676c6503636f6d"; then
            domain="google.com"
        elif echo "$request_data" | grep -q "636c6f7564666c61726503636f6d"; then
            domain="cloudflare.com"
        elif echo "$request_data" | grep -q "726f79646e73037879"; then
            domain="roydns.xyz"
        elif echo "$request_data" | grep -q "636861746770743"; then
            domain="chatgpt.com"
        else
            # Try to extract from the ASCII view line in the output
            domain=$(echo "$request_data" | grep "ASCII view:" | grep -oE "cloudflare|gmail|chatgpt|roydns" | head -1)
            if [ -n "$domain" ]; then
                case "$domain" in
                    "cloudflare") domain="cloudflare.com" ;;
                    "gmail") domain="gmail.com" ;;
                    "chatgpt") domain="chatgpt.com" ;;
                    "roydns") domain="roydns.xyz" ;;
                esac
            else
                domain="unknown"
            fi
        fi
    fi
    
    # Determine request type and fill appropriate columns
    local is_custom_domain=false
    if echo "$request_data" | grep -q "Custom domain detected - using encrypted ANS"; then
        is_custom_domain=true
    fi
    
    # Determine status
    if [ -n "$rr_rtt" ] && [ "$rr_rtt" != "" ]; then
        status="SUCCESS"
    else
        status="FAILED"
        rr_rtt="N/A"
    fi
    
    # Log the results - include all timing points
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp,$domain,$run_number,$tw6,$tw7,$tw8,$tw9,$tw10,$tw11,$tw19,$tw20,$tw21,$tw22,$tw23,$tw24,$rr_rtt,$status" >> "$RR_LOG_FILE"
    
    # Show progress
    echo "=== LOGGED ==="
    echo "Domain: $domain"
    echo "Run: $run_number"
    echo "Request Type: $([ "$is_custom_domain" = true ] && echo "Custom (Encrypted ANS)" || echo "Global (Normal DNS)")"
    echo "RR RTT: $rr_rtt ms"
    echo "Status: $status"
    echo "Timestamps captured:"
    echo "  TW6=$tw6 (Packet received)"
    echo "  TW7=$tw7 (Decryption start)"
    echo "  TW8=$tw8 (Decryption end)"
    if [ "$is_custom_domain" = true ]; then
        echo "  TW10=$tw10 (Send to custom DNS)"
        echo "  TW19=$tw19 (Custom DNS result)"
        echo "  TW20=$tw20 (ANS decryption start)"
        echo "  TW21=$tw21 (ANS decryption end)"
    else
        echo "  TW9=$tw9 (Send to global DNS)"
        echo "  TW11=$tw11 (Global DNS result)"
    fi
    echo "  TW22=$tw22 (Encrypt start)"
    echo "  TW23=$tw23 (Encrypt end)"
    echo "  TW24=$tw24 (Send to proxy)"
    echo "=============="
    echo ""
}

# Function to monitor RR logs in real-time
monitor_rr() {
    local run_counter=1
    local current_request_data=""
    local collecting_request=false
    
    echo "Starting RR monitoring..."
    echo "Waiting for proxy requests..."
    echo ""
    
    # Monitor the RR output file
    tail -f "$TEMP_LOG" | while read line; do
        echo "$line"
        
        # Check if this line indicates a new encrypted DNS connection from proxy
        if echo "$line" | grep -q "Encrypted DNS connection from:"; then
            # Start collecting data for this request
            collecting_request=true
            current_request_data="$line"
            echo "Detected encrypted connection from proxy"
            
        elif [ "$collecting_request" = true ]; then
            # Collect all lines for this request
            current_request_data="$current_request_data"$'\n'"$line"
            
            # Check if this is the end of the request (RR RTT line)
            if echo "$line" | grep -q "RR RTT:"; then
                # Process the complete request data
                process_request_data "$current_request_data" "$run_counter"
                
                # Reset for next request
                collecting_request=false
                current_request_data=""
                ((run_counter++))
            fi
        fi
    done
}

# Function to start RR with output logging
start_rr_with_logging() {
    echo "Starting RR with logging..."
    
    # Clear any existing temp log
    > "$TEMP_LOG"
    
    # Start RR and redirect output to temp log
    sudo python3 "$RR_SCRIPT" > "$TEMP_LOG" 2>&1 &
    RR_PID=$!
    
    echo "RR started with PID: $RR_PID"
    echo "Output logging to: $TEMP_LOG"
    
    # Wait a moment for RR to start
    sleep 2
    
    return $RR_PID
}

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ ! -z "$RR_PID" ]; then
        echo "Stopping RR (PID: $RR_PID)..."
        kill $RR_PID 2>/dev/null
    fi
    
    # Generate summary
    echo ""
    echo "Generating summary..."
    
    if [ -f "$RR_LOG_FILE" ]; then
        total_requests=$(grep -c "SUCCESS\|FAILED" "$RR_LOG_FILE")
        successful_requests=$(grep -c "SUCCESS" "$RR_LOG_FILE")
        custom_requests=$(grep -c "roydns.xyz" "$RR_LOG_FILE")
        global_requests=$((successful_requests - custom_requests))
        
        echo "=== RR MONITORING SUMMARY ===" >> "$RR_LOG_FILE"
        echo "Total requests processed: $total_requests" >> "$RR_LOG_FILE"
        echo "Successful requests: $successful_requests" >> "$RR_LOG_FILE"
        echo "Custom domain requests (roydns.xyz): $custom_requests" >> "$RR_LOG_FILE"
        echo "Global domain requests: $global_requests" >> "$RR_LOG_FILE"
        echo "Monitoring ended at: $(date)" >> "$RR_LOG_FILE"
        
        echo "Results saved to: $RR_LOG_FILE"
        echo "Total requests: $total_requests"
        echo "Successful: $successful_requests"
        echo "Custom domains: $custom_requests"
        echo "Global domains: $global_requests"
    fi
    
    # Clean up temp file
    rm -f "$TEMP_LOG"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Initialize log file with header
echo "RR Monitoring Started at $(date)" > "$RR_LOG_FILE"
echo "================================================" >> "$RR_LOG_FILE"
echo "Timestamp,Domain,Run,TW6,TW7,TW8,TW9,TW10,TW11,TW19,TW20,TW21,TW22,TW23,TW24,RR_RTT_ms,Status" >> "$RR_LOG_FILE"
echo "" >> "$RR_LOG_FILE"

# Clear DNS cache
clear_local_cache

# Start RR with logging
start_rr_with_logging

# Start monitoring in background
monitor_rr &
MONITOR_PID=$!

echo ""
echo "================================================"
echo "RR MONITOR IS READY!"
echo "================================================"
echo "Now run your client test script from the client PC"
echo "This script will automatically detect and log all requests"
echo ""
echo "Press Ctrl+C to stop monitoring and generate summary"
echo "================================================"
echo ""

# Wait for monitoring to complete or user interrupt
wait $MONITOR_PID
