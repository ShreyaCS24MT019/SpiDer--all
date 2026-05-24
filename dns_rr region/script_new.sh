#!/bin/bash

# RR Monitoring Script - Auto-detect and log timing when proxy calls
# Run this script ON THE RR PC before running client tests

# Configuration
RR_LOG_FILE="rr_monitor_$(date +%Y%m%d_%H%M%S).log"
TEMP_LOG="/tmp/rr_output.log"
RR_SCRIPT="refine.py"  # Replace with your actual RR script name
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
    
    # Extract timestamps from this specific request - FIXED patterns to match actual Python output
    local tw6=$(echo "$request_data" | grep -E "TIMESTAMP.*TW6.*RR.*RECEIVES.*PACKET.*FROM.*PROXY" | awk '{print $2}')
    local tw7=$(echo "$request_data" | grep -E "TIMESTAMP.*TW7.*BEGINS.*DECRYPTION.*FROM.*PROXY" | awk '{print $2}')
    local tw8=$(echo "$request_data" | grep -E "TIMESTAMP.*TW8.*ENDS.*DECRYPTION.*FROM.*PROXY" | awk '{print $2}')
    local tw9=$(echo "$request_data" | grep -E "TIMESTAMP.*TW9.*SENDS.*IT.*TO.*GLOBAL.*DNS" | awk '{print $2}')
    local tw11=$(echo "$request_data" | grep -E "TIMESTAMP.*TW11.*RECEIVES.*THE.*GLOBAL.*DNS.*RESULT" | awk '{print $2}')
    local tw12=$(echo "$request_data" | grep -E "TIMESTAMP.*TW12.*STARTS.*ENCRYPTING.*FOR.*ANS" | awk '{print $2}')
    local tw13=$(echo "$request_data" | grep -E "TIMESTAMP.*TW13.*ENDS.*ENCRYPTION.*FOR.*ANS" | awk '{print $2}')
    local tw14=$(echo "$request_data" | grep -E "TIMESTAMP.*TW14.*SENDS.*ENCRYPTED.*QUERY.*TO.*ANS" | awk '{print $2}')
    local tw19=$(echo "$request_data" | grep -E "TIMESTAMP.*TW19.*RECEIVES.*CUSTOM.*DNS.*RESULT" | awk '{print $2}')
    local tw20=$(echo "$request_data" | grep -E "TIMESTAMP.*TW20.*RECEIVES.*ENCRYPTED.*RESPONSE.*FROM.*ANS" | awk '{print $2}')
    local tw21=$(echo "$request_data" | grep -E "TIMESTAMP.*TW21.*STARTS.*DECRYPTING.*FROM.*ANS" | awk '{print $2}')
    local tw22_alt=$(echo "$request_data" | grep -E "TIMESTAMP.*TW22.*ENDS.*DECRYPTION.*FROM.*ANS" | awk '{print $2}')
    local tw22=$(echo "$request_data" | grep -E "TIMESTAMP.*TW22.*STARTS.*ENCRYPTING.*FOR.*PROXY" | awk '{print $2}')
    local tw23=$(echo "$request_data" | grep -E "TIMESTAMP.*TW23.*ENDS.*ENCRYPTION.*FOR.*PROXY" | awk '{print $2}')
    local tw24=$(echo "$request_data" | grep -E "TIMESTAMP.*TW24.*SENDS.*PACKET.*TO.*PROXY" | awk '{print $2}')
    local rr_rtt=$(echo "$request_data" | grep "RR RTT:" | awk '{print $3}' | sed 's/ms//')
    local powerdns_rtt=$(echo "$request_data" | grep "PowerDNS RTT:" | awk '{print $3}' | sed 's/ms//')
    local ans_rtt=$(echo "$request_data" | grep "ANS RTT:" | awk '{print $3}' | sed 's/ms//')
    
    # Extract domain from "Checking domain:" line - improved extraction
    local domain=$(echo "$request_data" | grep "🔍 Checking domain:" | awk '{print $4}' | sed 's/\.$//')
    
    # If domain extraction fails, try multiple methods
    if [ -z "$domain" ] || [ "$domain" = "" ]; then
        # Try without emoji
        domain=$(echo "$request_data" | grep "Checking domain:" | awk '{print $3}' | sed 's/\.$//')
    fi
    
    # If still no domain, try to extract from hex patterns or ASCII view
    if [ -z "$domain" ] || [ "$domain" = "" ]; then
        # Check for different domain hex patterns in the raw bytes
        if echo "$request_data" | grep -q "676f6f676c6503636f6d"; then
            domain="google.com"
        elif echo "$request_data" | grep -q "796f7574756265"; then
            domain="youtube.com"
        elif echo "$request_data" | grep -q "636c6f7564666c617265"; then
            domain="cloudflare.com"
        elif echo "$request_data" | grep -q "73706f74696679"; then
            domain="spotify.com"
        elif echo "$request_data" | grep -q "74656c656772616d"; then
            domain="telegram.com"
        elif echo "$request_data" | grep -q "726f79646e73037879"; then
            domain="roydns.xyz"
        elif echo "$request_data" | grep -q "69697464680261630269"; then
            domain="iitdh.ac.in"
        elif echo "$request_data" | grep -q "7a6f6d61746f"; then
            domain="zomato.com"
        elif echo "$request_data" | grep -q "7961686f6f"; then
            domain="yahoo.com"
        elif echo "$request_data" | grep -q "676d61696c"; then
            domain="gmail.com"
        elif echo "$request_data" | grep -q "636861746770743"; then
            domain="chatgpt.com"
        else
            # Try to extract from the ASCII view line in the output
            domain=$(echo "$request_data" | grep "ASCII view:" | grep -oE "[a-zA-Z0-9.-]+\.(com|org|net|xyz|io|in)" | head -1)
            if [ -z "$domain" ]; then
                # Last resort - check for common domain patterns in ASCII
                if echo "$request_data" | grep -qi "cloudflare"; then
                    domain="cloudflare.com"
                elif echo "$request_data" | grep -qi "google"; then
                    domain="google.com"
                elif echo "$request_data" | grep -qi "roydns"; then
                    domain="roydns.xyz"
                elif echo "$request_data" | grep -qi "chatgpt"; then
                    domain="chatgpt.com"
                elif echo "$request_data" | grep -qi "youtube"; then
                    domain="youtube.com"
                elif echo "$request_data" | grep -qi "spotify"; then
                    domain="spotify.com"
                elif echo "$request_data" | grep -qi "telegram"; then
                    domain="telegram.com"
                elif echo "$request_data" | grep -qi "iitdh"; then
                    domain="iitdh.ac.in"
                elif echo "$request_data" | grep -qi "zomato"; then
                    domain="zomato.com"
                elif echo "$request_data" | grep -qi "yahoo"; then
                    domain="yahoo.com"
                elif echo "$request_data" | grep -qi "gmail"; then
                    domain="gmail.com"
                else
                    domain="unknown"
                fi
            fi
        fi
    fi
    
    # Determine request type - FIXED LOGIC
    local is_custom_domain=false
    local request_type="Global"
    
    # Check for custom domain detection - look for the specific messages from your Python code
    if echo "$request_data" | grep -q "Custom domain detected - using encrypted ANS"; then
        is_custom_domain=true
        request_type="Custom"
    elif echo "$request_data" | grep -q "🔐 Custom domain detected - using encrypted ANS"; then
        is_custom_domain=true
        request_type="Custom"
    elif echo "$request_data" | grep -q "Sending to encrypted ANS"; then
        is_custom_domain=true
        request_type="Custom"
    elif echo "$request_data" | grep -q "🔐 Sending to encrypted ANS"; then
        is_custom_domain=true
        request_type="Custom"
    elif echo "$request_data" | grep -q "roydns.xyz" && (echo "$request_data" | grep -q "TW12\|TW13\|TW14\|TW19\|TW20\|TW21"); then
        # If we see roydns.xyz AND ANS-related timestamps, it's custom
        is_custom_domain=true
        request_type="Custom"
    elif echo "$request_data" | grep -q "Global domain - using normal PowerDNS"; then
        is_custom_domain=false
        request_type="Global"
    elif echo "$request_data" | grep -q "🌐 Global domain - using normal PowerDNS"; then
        is_custom_domain=false
        request_type="Global"
    elif echo "$request_data" | grep -q "TW9\|PowerDNS RTT"; then
        # If we see TW9 or PowerDNS RTT, it's likely global
        is_custom_domain=false
        request_type="Global"
    fi
    
    # Double-check: if domain is roydns.xyz, it should be custom
    if echo "$domain" | grep -q "roydns.xyz"; then
        is_custom_domain=true
        request_type="Custom"
    fi
    
    # Determine status
    if [ -n "$rr_rtt" ] && [ "$rr_rtt" != "" ]; then
        status="SUCCESS"
    else
        status="FAILED"
        rr_rtt="N/A"
    fi
    
    # Log the results - include all timing points with proper handling of empty values
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Replace empty values with empty string for CSV consistency
    tw6=${tw6:-""}
    tw7=${tw7:-""}
    tw8=${tw8:-""}
    tw9=${tw9:-""}
    tw11=${tw11:-""}
    tw12=${tw12:-""}
    tw13=${tw13:-""}
    tw14=${tw14:-""}
    tw19=${tw19:-""}
    tw20=${tw20:-""}
    tw21=${tw21:-""}
    tw22_alt=${tw22_alt:-""}
    tw22=${tw22:-""}
    tw23=${tw23:-""}
    tw24=${tw24:-""}
    powerdns_rtt=${powerdns_rtt:-""}
    ans_rtt=${ans_rtt:-""}
    
    echo "$timestamp,$domain,$run_number,$request_type,$tw6,$tw7,$tw8,$tw9,$tw11,$tw12,$tw13,$tw14,$tw19,$tw20,$tw21,$tw22_alt,$tw22,$tw23,$tw24,$rr_rtt,$powerdns_rtt,$ans_rtt,$status" >> "$RR_LOG_FILE"
    
    # Show progress
    echo "=== LOGGED ==="
    echo "Domain: $domain"
    echo "Run: $run_number"
    echo "Request Type: $request_type"
    echo "RR RTT: $rr_rtt ms"
    if [ -n "$powerdns_rtt" ] && [ "$powerdns_rtt" != "" ]; then
        echo "PowerDNS RTT: $powerdns_rtt ms"
    fi
    if [ -n "$ans_rtt" ] && [ "$ans_rtt" != "" ]; then
        echo "ANS RTT: $ans_rtt ms"
    fi
    echo "Status: $status"
    echo "Timestamps captured:"
    echo "  TW6=$tw6 (Packet received)"
    echo "  TW7=$tw7 (Decryption start)"
    echo "  TW8=$tw8 (Decryption end)"
    if [ "$is_custom_domain" = true ]; then
        echo "  TW12=$tw12 (ANS encryption start)"
        echo "  TW13=$tw13 (ANS encryption end)"
        echo "  TW14=$tw14 (Send to ANS)"
        echo "  TW19=$tw19 (Custom DNS result)"
        echo "  TW20=$tw20 (ANS response received)"
        echo "  TW21=$tw21 (ANS decryption start)"
        echo "  TW22_alt=$tw22_alt (ANS decryption end)"
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
    local pending_tw6=""
    
    echo "Starting RR monitoring..."
    echo "Waiting for proxy requests..."
    echo ""
    
    # Monitor the RR output file
    tail -f "$TEMP_LOG" | while read line; do
        echo "$line"
        
        # Check for TW6 timestamp (might come before connection message)
        if echo "$line" | grep -q "TIMESTAMP.*TW6"; then
            pending_tw6="$line"
        fi
        
        # Check if this line indicates a new encrypted DNS connection from proxy
        if echo "$line" | grep -q "Encrypted DNS connection from:"; then
            # Start collecting data for this request
            collecting_request=true
            # Include any pending TW6 timestamp
            if [ -n "$pending_tw6" ]; then
                current_request_data="$pending_tw6"$'\n'"$line"
                pending_tw6=""
            else
                current_request_data="$line"
            fi
            echo "Detected encrypted connection from proxy"
            
        elif [ "$collecting_request" = true ]; then
            # Collect all lines for this request
            current_request_data="$current_request_data"$'\n'"$line"
            
            # Check if this is the end of the request (RR RTT line or completion message)
            if echo "$line" | grep -q "RR RTT:" || echo "$line" | grep -q "Encrypted DNS response sent successfully!"; then
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
        custom_requests=$(grep -c ",Custom," "$RR_LOG_FILE")
        global_requests=$(grep -c ",Global," "$RR_LOG_FILE")
        
        echo "=== RR MONITORING SUMMARY ===" >> "$RR_LOG_FILE"
        echo "Total requests processed: $total_requests" >> "$RR_LOG_FILE"
        echo "Successful requests: $successful_requests" >> "$RR_LOG_FILE"
        echo "Custom domain requests: $custom_requests" >> "$RR_LOG_FILE"
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

# Initialize log file with header - Updated header without TW10
echo "RR Monitoring Started at $(date)" > "$RR_LOG_FILE"
echo "================================================" >> "$RR_LOG_FILE"
echo "Timestamp,Domain,Run,Type,TW6,TW7,TW8,TW9,TW11,TW12,TW13,TW14,TW19,TW20,TW21,TW22_ANS_decrypt_end,TW22,TW23,TW24,RR_RTT_ms,PowerDNS_RTT_ms,ANS_RTT_ms,Status" >> "$RR_LOG_FILE"
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
