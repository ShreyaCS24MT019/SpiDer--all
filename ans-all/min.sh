#!/bin/bash

# ANS Monitoring Script (No Encryption)
# Run this ON THE ANS MACHINE where ANS server is running

# Configuration
ANS_LOG_FILE="ans_monitor_$(date +%Y%m%d_%H%M%S).log"
TEMP_LOG="/tmp/ans_output.log"
ANS_SCRIPT="non_encrypt.py"
MONITOR_DURATION=3600  # 1 hour

# Function to process complete request data
process_ans_data() {
    local log_data="$1"
    local run_number="$2"

    local tw12=$(echo "$log_data" | grep "TW12 ANS RECEIVES PACKET FROM RR" | awk '{print $2}')
    local tw13=$(echo "$log_data" | grep "TW13 received query from RR" | awk '{print $2}')
    local tw14=$(echo "$log_data" | grep "TW14 starting the processing query" | awk '{print $2}')
    local tw15=$(echo "$log_data" | grep "TW15 ending the processing of query" | awk '{print $2}')
    local tw16=$(echo "$log_data" | grep "TW16 response preparation started at ANS" | awk '{print $2}')
    local tw17=$(echo "$log_data" | grep "TW17 response preparation ends at ANS" | awk '{print $2}')
    local tw18=$(echo "$log_data" | grep "TW18 sending back the response to RR" | awk '{print $2}')
    local ans_rtt=$(echo "$log_data" | grep "ANS RTT:" | awk '{print $3}' | sed 's/ms//')

    local domain=$(echo "$log_data" | grep "ASCII view:" | sed -n 's/.*ASCII view: \(.*\)/\1/p' | tr -d '[:space:]')
    [[ -z "$domain" ]] && domain="unknown"

    local status="FAILED"
    [[ -n "$ans_rtt" && "$ans_rtt" != "N/A" ]] && status="SUCCESS" || ans_rtt="N/A"

    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp,$domain,$run_number,$tw12,$tw13,$tw14,$tw15,$tw16,$tw17,$tw18,$ans_rtt,$status" >> "$ANS_LOG_FILE"

    echo "=== LOGGED ==="
    echo "Domain: $domain"
    echo "Run: $run_number"
    echo "ANS RTT: $ans_rtt ms"
    echo "Status: $status"
    echo "=========================="
    echo ""
}

monitor_ans() {
    local run_counter=1
    local current_data=""
    local collecting=false

    echo "Monitoring ANS logs (NO ENCRYPTION MODE)..."
    echo "Waiting for incoming queries..."

    tail -n0 -F "$TEMP_LOG" | while read -r line; do
        echo "$line"

        if echo "$line" | grep -q "TW12 ANS RECEIVES PACKET FROM RR\|TW13 received query from RR"; then
            collecting=true
            current_data="$line"
            echo "Detected new request at $(echo "$line" | awk '{print $2}')"
        elif [ "$collecting" = true ]; then
            current_data="$current_data"$'\n'"$line"

            if echo "$line" | grep -q "ANS RTT:"; then
                process_ans_data "$current_data" "$run_counter"
                collecting=false
                current_data=""
                ((run_counter++))
            fi
        fi
    done
}

start_ans_with_logging() {
    echo "Starting ANS Python server (NO ENCRYPTION)..."
    > "$TEMP_LOG"
    sudo python3 "$ANS_SCRIPT" > "$TEMP_LOG" 2>&1 &
    ANS_PID=$!
    echo "ANS Server started with PID: $ANS_PID"
    sleep 2
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    if [[ ! -z "$ANS_PID" ]]; then
        echo "Stopping ANS server (PID: $ANS_PID)..."
        kill "$ANS_PID" 2>/dev/null
    fi

    echo ""
    echo "Generating summary..."
    if [[ -f "$ANS_LOG_FILE" ]]; then
        total=$(grep -c "SUCCESS\|FAILED" "$ANS_LOG_FILE")
        success=$(grep -c "SUCCESS" "$ANS_LOG_FILE")

        {
            echo "=== ANS MONITORING SUMMARY (NO ENCRYPTION) ==="
            echo "Total requests processed: $total"
            echo "Successful requests: $success"
            echo "Monitoring ended at: $(date)"
        } >> "$ANS_LOG_FILE"

        echo "Results saved to: $ANS_LOG_FILE"
        echo "Total: $total, Successful: $success"
    fi

    rm -f "$TEMP_LOG"
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "ANS Monitoring Started at $(date) - NO ENCRYPTION MODE" > "$ANS_LOG_FILE"
{
    echo "============================================"
    echo "Timestamp,Domain,Run,TW12,TW13,TW14,TW15,TW16,TW17,TW18,ANS_RTT_ms,Status"
    echo ""
} >> "$ANS_LOG_FILE"

start_ans_with_logging
monitor_ans &
MONITOR_PID=$!
wait "$MONITOR_PID"
