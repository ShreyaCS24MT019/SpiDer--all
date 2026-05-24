import subprocess
import time
import csv
import statistics
from datetime import datetime

domains = [
    "google.com", "youtube.com", "cloudflare.com", "spotify.com", 
    "telegram.com", "iitdh.ac.in", "zomato.com", "chatgpt.com", 
    "yahoo.com", "gmail.com", "roydns.xyz"
]

def clear_dns_cache():
    """Clear DNS cache specifically for DNSCrypt-proxy"""
    try:
        # Restart DNSCrypt-proxy to clear its cache
        subprocess.run(["sudo", "systemctl", "restart", "dnscrypt-proxy"], 
                      check=True, timeout=15, capture_output=True)
        print("DNSCrypt-proxy restarted (cache cleared)")
        time.sleep(3)  # Wait for restart to complete
        
    except subprocess.CalledProcessError:
        print("Warning: Could not restart DNSCrypt-proxy")
    except subprocess.TimeoutExpired:
        print("Warning: DNSCrypt-proxy restart timed out")
    except Exception as e:
        print(f"Warning: Cache clearing error: {e}")

def run_dig_query(domain, dns_server, port=53, query_type="A"):
    """Run dig command and parse output"""
    cmd = ["dig", "+stats", "+yaml", "+nocookie", domain, query_type, f"@{dns_server}", "-p", str(port)]
    
    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    end_time = time.time()
    
    output = result.stdout
    error = result.stderr
    
    # Parse dig output for timing information
    query_time = None
    response_time = None
    server_time = None
    msg_size = None
    
    for line in output.split('\n'):
        if "Query time:" in line:
            query_time = int(line.split()[2])
        elif "MSG SIZE" in line:
            msg_size = int(line.split()[5])
        elif "time:" in line and "msec" in line and not "Query" in line:
            try:
                server_time = float(line.split()[3])
            except:
                pass
    
    total_time = (end_time - start_time) * 1000  # Convert to milliseconds
    
    return {
        'query_time': query_time,
        'response_time': server_time,
        'total_rtt': total_time,
        'packet_size': msg_size,
        'success': result.returncode == 0
    }

def test_dnscrypt_performance():
    """Test DNSCrypt performance with cache clearing"""
    results = []
    
    for domain in domains:
        domain_results = []
        print(f"Testing {domain} with DNSCrypt...")
        
        for i in range(100):
            if i % 10 == 0:
                print(f"  Iteration {i+1}/100")
                clear_dns_cache()  # Clear cache every 10 queries
                time.sleep(2)  # Wait for service to stabilize
            
            result = run_dig_query(domain, "127.0.0.1", 5354)
            result['domain'] = domain
            result['iteration'] = i + 1
            result['dns_type'] = 'dnscrypt'
            domain_results.append(result)
            time.sleep(0.1)  # Small delay between queries
        
        results.extend(domain_results)
    
    return results

def test_normal_dns_performance():
    """Test normal DNS performance"""
    results = []
    
    for domain in domains:
        domain_results = []
        print(f"Testing {domain} with normal DNS...")
        
        for i in range(100):
            if i % 10 == 0:
                print(f"  Iteration {i+1}/100")
                # For normal DNS, we don't need to clear DNSCrypt cache
                time.sleep(1)  # Small pause for consistency
            
            result = run_dig_query(domain, "1.1.1.1")  # Using Cloudflare DNS
            result['domain'] = domain
            result['iteration'] = i + 1
            result['dns_type'] = 'normal'
            domain_results.append(result)
            time.sleep(0.1)  # Small delay between queries
        
        results.extend(domain_results)
    
    return results

def save_to_csv(results, filename):
    """Save results to CSV file"""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'domain', 'iteration', 'dns_type', 'query_time', 
                     'response_time', 'total_rtt', 'packet_size', 'success']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            result['timestamp'] = datetime.now().isoformat()
            writer.writerow(result)

def main():
    print("Starting DNS Performance Analysis")
    print("=" * 50)
    print(f"Testing {len(domains)} domains, 100 iterations each")
    print(f"Total queries: {len(domains) * 100 * 2} (DNSCrypt + Normal DNS)")
    print("=" * 50)
    
    # Start DNSCrypt proxy in background
    print("Starting DNSCrypt proxy...")
    dnscrypt_process = subprocess.Popen([
        "sudo", "dnscrypt-proxy", 
        "-config", "/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Wait for DNSCrypt to start
    time.sleep(5)
    
    try:
        # Test DNSCrypt performance
        print("\n" + "="*50)
        print("Testing DNSCrypt performance...")
        print("="*50)
        dnscrypt_results = test_dnscrypt_performance()
        
        # Test normal DNS performance
        print("\n" + "="*50)
        print("Testing normal DNS performance...")
        print("="*50)
        normal_results = test_normal_dns_performance()
        
        # Combine results
        all_results = dnscrypt_results + normal_results
        
        # Save to CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dns_performance_{timestamp}.csv"
        save_to_csv(all_results, filename)
        
        print(f"\n" + "="*50)
        print(f"Results saved to {filename}")
        print(f"Total tests completed: {len(all_results)}")
        print(f"DNSCrypt tests: {len(dnscrypt_results)}")
        print(f"Normal DNS tests: {len(normal_results)}")
        print("="*50)
        
        # Calculate basic statistics
        dnscrypt_times = [r['total_rtt'] for r in dnscrypt_results if r['success']]
        normal_times = [r['total_rtt'] for r in normal_results if r['success']]
        
        if dnscrypt_times and normal_times:
            print(f"Average DNSCrypt RTT: {statistics.mean(dnscrypt_times):.2f} ms")
            print(f"Average Normal DNS RTT: {statistics.mean(normal_times):.2f} ms")
            print(f"Encryption overhead: {statistics.mean(dnscrypt_times) - statistics.mean(normal_times):.2f} ms")
        
    finally:
        # Stop DNSCrypt proxy
        dnscrypt_process.terminate()
        dnscrypt_process.wait()
        print("DNSCrypt proxy stopped")

if __name__ == "__main__":
    main()
