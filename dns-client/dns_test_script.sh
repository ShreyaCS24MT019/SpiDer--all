#!/bin/bash

# DNS Testing Script with Cache Clearing
# Tests 10 domains, 10 times each, with cache clearing between tests

# Configuration
DOMAINS=("roydns.xyz"   )
CLIENT_SCRIPT="client_rtt.py" 
LOG_FILE="dns_test_results_$(date +%Y%m%d_%H%M%S).log"
RUNS_PER_DOMAIN=50

# Function to clear DNS cache
clear_dns_cache() {
    echo "Clearing DNS cache..."
    sudo resolvectl flush-caches 2>/dev/null
    sudo systemctl restart systemd-resolved 2>/dev/null
    sleep 1
}

# Function to extract timing from client output
extract_timing() {
    local output="$1"
    local tw1=$(echo "$output" | grep "TIMESTAMP.*TW1" | head -1 | awk '{print $2}')
    local tw29=$(echo "$output" | grep "TIMESTAMP.*TW29" | head -1 | awk '{print $2}')
    local client_rtt=$(echo "$output" | grep "CLIENT RTT:" | awk '{print $3}' | sed 's/ms//')
    
    echo "$tw1,$tw29,$client_rtt"
}

# Initialize log file with header
echo "DNS Testing Started at $(date)" > "$LOG_FILE"
echo "================================================" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Main testing loop
for domain in "${DOMAINS[@]}"; do
    echo "Testing domain: $domain" | tee -a "$LOG_FILE"
    echo "Domain,Run,TW1,TW29,Client_RTT_ms,Status" >> "$LOG_FILE"
    echo "----------------------------------------" >> "$LOG_FILE"
    
    for run in $(seq 1 $RUNS_PER_DOMAIN); do
        echo "Run $run for $domain..."
        
        # Clear cache before each test
        clear_dns_cache
        
        # Run the DNS client and capture output
        output=$(sudo python3 "$CLIENT_SCRIPT" "$domain" 2>&1)
        exit_code=$?
        
        # Extract timing information
        timing_data=$(extract_timing "$output")
        
        # Parse timing data
        IFS=',' read -r tw1 tw29 client_rtt <<< "$timing_data"
        
        # Determine status
        if [ $exit_code -eq 0 ] && [ -n "$client_rtt" ]; then
            status="SUCCESS"
        else
            status="FAILED"
            client_rtt="N/A"
        fi
        
        # Log the results
        echo "$domain,$run,$tw1,$tw29,$client_rtt,$status" >> "$LOG_FILE"
        
        # Show progress
        echo "  Run $run: RTT=$client_rtt ms, Status=$status"
        
        # Small delay between runs
        sleep 2
    done
    
    echo "" >> "$LOG_FILE"
    echo "Completed testing $domain"
    echo ""
done

# Generate summary
echo "" >> "$LOG_FILE"
echo "================================================" >> "$LOG_FILE"
echo "SUMMARY STATISTICS" >> "$LOG_FILE"
echo "================================================" >> "$LOG_FILE"

for domain in "${DOMAINS[@]}"; do
    echo "" >> "$LOG_FILE"
    echo "Domain: $domain" >> "$LOG_FILE"
    echo "----------------" >> "$LOG_FILE"
    
    # Calculate statistics for this domain
    grep "^$domain," "$LOG_FILE" | awk -F',' '
    BEGIN { 
        count=0; sum=0; min=999999; max=0; success=0 
    }
    $5 != "N/A" && $6 == "SUCCESS" { 
        count++; 
        sum+=$5; 
        success++;
        if($5 < min) min=$5; 
        if($5 > max) max=$5;
    }
    $6 == "SUCCESS" { success++ }
    END {
        if(count > 0) {
            avg = sum/count
            printf "Successful runs: %d/10\n", success
            printf "Average RTT: %.2f ms\n", avg
            printf "Min RTT: %.2f ms\n", min
            printf "Max RTT: %.2f ms\n", max
        } else {
            print "No successful runs"
        }
    }' >> "$LOG_FILE"
done

# Final completion message
echo "" >> "$LOG_FILE"
echo "Testing completed at $(date)" >> "$LOG_FILE"
echo "Results saved to: $LOG_FILE" >> "$LOG_FILE"

echo "================================================"
echo "DNS Testing Complete!"
echo "Results saved to: $LOG_FILE"
echo "================================================"

# Show quick summary on terminal
echo ""
echo "Quick Summary:"
echo "--------------"
for domain in "${DOMAINS[@]}"; do
    success_count=$(grep "^$domain," "$LOG_FILE" | grep "SUCCESS" | wc -l)
    avg_rtt=$(grep "^$domain," "$LOG_FILE" | awk -F',' '$5 != "N/A" && $6 == "SUCCESS" {sum+=$5; count++} END {if(count>0) print sum/count; else print "N/A"}')
    printf "%-15s: %d/10 successful, Avg RTT: %s ms\n" "$domain" "$success_count" "$avg_rtt"
done
