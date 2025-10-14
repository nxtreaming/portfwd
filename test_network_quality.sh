#!/bin/bash
# Network Quality Test Script for UDP Forwarder Diagnosis
# Tests packet loss, latency, and jitter to diagnose freeze/hang issues

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVER="${1:-}"
PING_COUNT=100
MTR_CYCLES=50
IPERF_DURATION=30
IPERF_BANDWIDTH="10M"

# Usage
if [ -z "$SERVER" ]; then
    echo "Usage: $0 <udpfwd_server_ip_or_hostname>"
    echo ""
    echo "Example: $0 vpn.example.com"
    echo "         $0 192.168.1.100"
    exit 1
fi

echo "=========================================="
echo "Network Quality Test for UDP Forwarder"
echo "=========================================="
echo "Target Server: $SERVER"
echo "Date: $(date)"
echo ""

# Function to print status
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        "GOOD")
            echo -e "${GREEN}✅ GOOD${NC}: $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  WARNING${NC}: $message"
            ;;
        "BAD")
            echo -e "${RED}❌ BAD${NC}: $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Test 1: Basic Connectivity
echo "=========================================="
echo "Test 1: Basic Connectivity"
echo "=========================================="
if ping -c 1 -W 5 "$SERVER" > /dev/null 2>&1; then
    print_status "GOOD" "Server is reachable"
else
    print_status "BAD" "Server is NOT reachable!"
    echo "Cannot continue tests. Please check:"
    echo "  1. Server IP/hostname is correct"
    echo "  2. Server is online"
    echo "  3. Firewall allows ICMP"
    exit 1
fi
echo ""

# Test 2: Packet Loss Test
echo "=========================================="
echo "Test 2: Packet Loss Test (${PING_COUNT} packets)"
echo "=========================================="
echo "Testing... (this may take a minute)"
PING_OUTPUT=$(ping -c $PING_COUNT "$SERVER" 2>&1)
PACKET_LOSS=$(echo "$PING_OUTPUT" | grep -oP '\d+(?=% packet loss)' || echo "0")
AVG_RTT=$(echo "$PING_OUTPUT" | grep -oP 'min/avg/max[^=]*= [^/]*/\K[^/]*' || echo "N/A")

echo "Results:"
echo "  Packet Loss: ${PACKET_LOSS}%"
echo "  Average RTT: ${AVG_RTT} ms"
echo ""

if [ "$PACKET_LOSS" -lt 1 ]; then
    print_status "GOOD" "Excellent network quality (<1% loss)"
    echo "  → udpfwd should work perfectly"
elif [ "$PACKET_LOSS" -lt 5 ]; then
    print_status "WARNING" "Acceptable network quality (1-5% loss)"
    echo "  → udpfwd should work, but may have occasional issues"
    echo "  → Consider optimizing OpenVPN configuration"
elif [ "$PACKET_LOSS" -lt 10 ]; then
    print_status "BAD" "Poor network quality (5-10% loss)"
    echo "  → This is likely causing freeze/hang issues!"
    echo "  → OpenVPN will struggle to maintain connection"
    echo "  → Recommended: Improve network or use TCP mode"
else
    print_status "BAD" "Very poor network quality (>10% loss)"
    echo "  → This is DEFINITELY causing freeze/hang issues!"
    echo "  → UDP forwarding is not viable with this network quality"
    echo "  → MUST improve network or switch to TCP mode"
fi
echo ""

# Test 3: Route Quality (if mtr is available)
echo "=========================================="
echo "Test 3: Route Quality Analysis"
echo "=========================================="
if command -v mtr &> /dev/null; then
    echo "Testing route quality (${MTR_CYCLES} cycles)..."
    echo "This may take 1-2 minutes..."
    echo ""
    
    MTR_OUTPUT=$(mtr --report --report-cycles $MTR_CYCLES --no-dns "$SERVER" 2>&1)
    echo "$MTR_OUTPUT"
    echo ""
    
    # Analyze MTR output for problematic hops
    PROBLEMATIC_HOPS=$(echo "$MTR_OUTPUT" | awk '$NF ~ /[5-9][0-9]\./ || $NF ~ /[1-9][0-9][0-9]\./ {print $0}' | wc -l)
    
    if [ "$PROBLEMATIC_HOPS" -gt 0 ]; then
        print_status "WARNING" "Found ${PROBLEMATIC_HOPS} hop(s) with >5% loss"
        echo "  → Network path has quality issues"
        echo "  → Consider using a different route/VPN"
    else
        print_status "GOOD" "All hops have good quality"
    fi
else
    echo "mtr not installed. Skipping route analysis."
    echo "Install with: sudo apt-get install mtr (Debian/Ubuntu)"
    echo "           or: sudo yum install mtr (CentOS/RHEL)"
fi
echo ""

# Test 4: UDP Throughput Test (if iperf3 is available)
echo "=========================================="
echo "Test 4: UDP Throughput & Loss Test"
echo "=========================================="
if command -v iperf3 &> /dev/null; then
    echo "NOTE: This test requires iperf3 server running on $SERVER"
    echo "      If server is not running, this test will fail (that's OK)"
    echo ""
    read -p "Run iperf3 UDP test? (y/N): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Testing UDP throughput (${IPERF_DURATION} seconds at ${IPERF_BANDWIDTH})..."
        
        if IPERF_OUTPUT=$(iperf3 -c "$SERVER" -u -b "$IPERF_BANDWIDTH" -t "$IPERF_DURATION" 2>&1); then
            echo "$IPERF_OUTPUT"
            echo ""
            
            # Extract loss percentage
            IPERF_LOSS=$(echo "$IPERF_OUTPUT" | grep -oP '\(\K[0-9.]+(?=%)' | tail -1 || echo "N/A")
            
            if [ "$IPERF_LOSS" != "N/A" ]; then
                echo "UDP Loss Rate: ${IPERF_LOSS}%"
                
                if (( $(echo "$IPERF_LOSS < 1" | bc -l) )); then
                    print_status "GOOD" "Excellent UDP performance"
                elif (( $(echo "$IPERF_LOSS < 5" | bc -l) )); then
                    print_status "WARNING" "Acceptable UDP performance"
                else
                    print_status "BAD" "Poor UDP performance - this explains freeze/hang!"
                fi
            fi
        else
            echo "iperf3 test failed (server not running or not accessible)"
            echo "This is optional - you can skip this test"
        fi
    else
        echo "Skipped iperf3 test"
    fi
else
    echo "iperf3 not installed. Skipping UDP throughput test."
    echo "Install with: sudo apt-get install iperf3 (Debian/Ubuntu)"
    echo "           or: sudo yum install iperf3 (CentOS/RHEL)"
fi
echo ""

# Summary and Recommendations
echo "=========================================="
echo "Summary & Recommendations"
echo "=========================================="
echo ""

if [ "$PACKET_LOSS" -lt 1 ]; then
    echo "🎉 Network Quality: EXCELLENT"
    echo ""
    echo "Your network is in great shape! If you're still experiencing"
    echo "freeze/hang issues, the problem is likely:"
    echo "  1. udpfwd configuration (check timeout settings)"
    echo "  2. OpenVPN configuration (check keepalive)"
    echo "  3. System resources (CPU/memory)"
    echo ""
    echo "Recommended udpfwd command:"
    echo "  ./udpfwd 0.0.0.0:1194 $SERVER:1194 -C 100 -t 300"
    
elif [ "$PACKET_LOSS" -lt 5 ]; then
    echo "⚠️  Network Quality: ACCEPTABLE"
    echo ""
    echo "Your network has minor quality issues. To improve stability:"
    echo ""
    echo "1. Optimize OpenVPN configuration:"
    echo "   keepalive 5 30"
    echo "   ping-restart 60"
    echo "   mssfix 1200"
    echo "   compress lz4-v2"
    echo ""
    echo "2. Disable udpfwd timeout:"
    echo "   ./udpfwd 0.0.0.0:1194 $SERVER:1194 -C 100 -t 0"
    echo ""
    echo "3. Increase UDP buffers:"
    echo "   sudo sysctl -w net.core.rmem_max=26214400"
    echo "   sudo sysctl -w net.core.wmem_max=26214400"
    
elif [ "$PACKET_LOSS" -lt 10 ]; then
    echo "❌ Network Quality: POOR"
    echo ""
    echo "Your network quality is causing the freeze/hang issues!"
    echo ""
    echo "IMMEDIATE ACTIONS:"
    echo "1. Switch from WiFi to wired connection (if possible)"
    echo "2. Test at different times of day"
    echo "3. Check for bandwidth-heavy applications"
    echo ""
    echo "CONFIGURATION CHANGES:"
    echo "1. Use aggressive OpenVPN keepalive:"
    echo "   keepalive 3 15"
    echo "   ping-restart 30"
    echo ""
    echo "2. Disable udpfwd timeout:"
    echo "   ./udpfwd 0.0.0.0:1194 $SERVER:1194 -C 100 -t 0"
    echo ""
    echo "LONG-TERM SOLUTION:"
    echo "Consider switching to TCP mode for better reliability:"
    echo "   ./tcpfwd 0.0.0.0:1194 $SERVER:1194"
    
else
    echo "❌ Network Quality: VERY POOR"
    echo ""
    echo "Your network is NOT suitable for UDP forwarding!"
    echo ""
    echo "The ${PACKET_LOSS}% packet loss is far too high for UDP-based VPN."
    echo "This is the ROOT CAUSE of your freeze/hang issues."
    echo ""
    echo "REQUIRED ACTIONS:"
    echo "1. Improve network quality:"
    echo "   - Use wired connection instead of WiFi"
    echo "   - Upgrade your internet plan"
    echo "   - Contact your ISP about quality issues"
    echo "   - Try a different network/location"
    echo ""
    echo "2. OR switch to TCP mode:"
    echo "   - Use tcpfwd instead of udpfwd"
    echo "   - Configure OpenVPN to use TCP"
    echo "   - TCP is slower but much more reliable"
    echo ""
    echo "UDP forwarding will NOT work reliably with this network quality!"
fi

echo ""
echo "=========================================="
echo "Test completed: $(date)"
echo "=========================================="
echo ""
echo "Save this output for troubleshooting:"
echo "  $0 $SERVER > network_test_$(date +%Y%m%d_%H%M%S).txt"
