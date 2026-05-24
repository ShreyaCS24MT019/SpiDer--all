#!/usr/bin/env python3
"""
DNS Client with Debug and Troubleshooting
Sends DNS queries through proxy with detailed error handling
"""

import socket
import struct
import sys
import time

class DNSClient:
    def __init__(self, proxy_ip="10.230.3.85", proxy_port=53):
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.timeout = 10  # Increased timeout for debugging
        
    def create_dns_query(self, domain, query_type="A"):
        """Create DNS query packet"""
        #print(f"TIMESTAMP: {time.time():.6f} - TW1 Client starts")
        print(f"Creating DNS query for {domain} type {query_type}")
        
        # Transaction ID (random)
        import random
        transaction_id = random.randint(1, 65535)
        print(f"Transaction ID: {transaction_id}")
        
        # Flags: Standard query (0x0100)
        flags = 0x0100
        
        # Counts
        questions = 1
        answers = 0
        authority = 0
        additional = 0
        
        # Header: 12 bytes
        header = struct.pack('!HHHHHH', transaction_id, flags, questions, 
                           answers, authority, additional)
        
        # Question section
        qname = b''
        for part in domain.split('.'):
            if len(part) > 63:
                raise ValueError(f"Domain part too long: {part}")
            qname += struct.pack('!B', len(part)) + part.encode('ascii')
        qname += b'\x00'  # End of name
        
        # Query type and class
        type_map = {
            'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'MX': 15, 'TXT': 16, 'AAAA': 28
        }
        qtype = type_map.get(query_type.upper(), 1)
        qclass = 1  # IN (Internet)
        
        question = qname + struct.pack('!HH', qtype, qclass)
        
        query = header + question
        print(f"Query packet size: {len(query)} bytes")
        return query, transaction_id
    
    def parse_dns_response(self, response, expected_transaction_id):
        """Parse DNS response packet"""
        if len(response) < 12:
            return False, "Response too short"
        
        # Parse header
        header = struct.unpack('!HHHHHH', response[:12])
        transaction_id, flags, questions, answers, authority, additional = header
        
        print(f"Response transaction ID: {transaction_id}")
        print(f"Expected transaction ID: {expected_transaction_id}")
        
        if transaction_id != expected_transaction_id:
            return False, f"Transaction ID mismatch: got {transaction_id}, expected {expected_transaction_id}"
        
        # Check response code
        rcode = flags & 0x000F
        response_codes = {
            0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 
            3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"
        }
        rcode_name = response_codes.get(rcode, f"UNKNOWN({rcode})")
        
        print(f"Response code: {rcode_name}")
        print(f"Questions: {questions}, Answers: {answers}")
        print(f"Authority: {authority}, Additional: {additional}")
        
        if rcode != 0:
            return False, f"DNS error: {rcode_name}"
        
        if answers == 0:
            return False, "No answers in response"
        
        # Parse answers (simplified)
        offset = 12
        
        # Skip question section
        for _ in range(questions):
            # Skip qname
            while offset < len(response) and response[offset] != 0:
                if response[offset] & 0xC0 == 0xC0:  # Compression
                    offset += 2
                    break
                else:
                    offset += response[offset] + 1
            if offset < len(response) and response[offset] == 0:
                offset += 1
            offset += 4  # Skip qtype and qclass
        
        # Parse answer section
        answer_results = []
        for _ in range(answers):
            if offset >= len(response):
                break
                
            # Skip name (with compression support)
            if offset < len(response) and response[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(response) and response[offset] != 0:
                    offset += response[offset] + 1
                if offset < len(response):
                    offset += 1
            
            if offset + 10 > len(response):
                break
                
            # Parse answer record
            atype, aclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
            offset += 10
            
            if offset + rdlength > len(response):
                break
                
            rdata = response[offset:offset+rdlength]
            offset += rdlength
            
            # Parse based on type
            if atype == 1 and rdlength == 4:  # A record
                ip = socket.inet_ntoa(rdata)
                answer_results.append(f"A: {ip}")
            elif atype == 28 and rdlength == 16:  # AAAA record
                ip = socket.inet_ntop(socket.AF_INET6, rdata)
                answer_results.append(f"AAAA: {ip}")
            else:
                answer_results.append(f"Type {atype}: {rdlength} bytes")
        
        return True, answer_results
    
    def test_connectivity(self):
        """Test basic connectivity to proxy"""
        print(f"Testing connectivity to proxy {self.proxy_ip}:{self.proxy_port}")
        
        try:
            # Test TCP connection first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.proxy_ip, self.proxy_port))
            sock.close()
            
            if result == 0:
                print("✓ TCP connection to proxy successful")
            else:
                print(f"✗ TCP connection failed with error {result}")
                
        except Exception as e:
            print(f"✗ TCP connection test failed: {e}")
        
        try:
            # Test UDP socket creation
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            # Try to bind to see if we can create UDP socket
            sock.bind(('', 0))
            local_port = sock.getsockname()[1]
            print(f"✓ UDP socket created, local port: {local_port}")
            sock.close()
            
        except Exception as e:
            print(f"✗ UDP socket test failed: {e}")
    
    def query_dns(self, domain, query_type="A"):
        """Send DNS query and get response"""
        print(f"\n{'='*50}")
        print(f"DNS Query: {domain} {query_type}")
        print(f"Proxy: {self.proxy_ip}:{self.proxy_port}")
        print(f"{'='*50}")
        
        try:
            # Create query packet
            query_packet, transaction_id = self.create_dns_query(domain, query_type)
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            print(f"Sending query to proxy...")
            
            # TIMING: Record client start time
            client_start_time = time.time()
            print(f"TIMESTAMP: {time.time():.6f} - Client sends query TW1")
            # Send query
            bytes_sent = sock.sendto(query_packet, (self.proxy_ip, self.proxy_port))
            print(f"Sent {bytes_sent} bytes to proxy")
            
            # Wait for response
            print("Waiting for response...")
            try:
                response_data, addr = sock.recvfrom(1024)
                
                # TIMING: Record client end time and calculate RTT
                client_end_time = time.time()
                client_rtt = (client_end_time - client_start_time) * 1000
                print(f"TIMESTAMP: {time.time():.6f} - RECIEVED AT CLIENT TW29")
                print(f"Received {len(response_data)} bytes from {addr}")
                print(f"CLIENT RTT: {client_rtt:.2f}ms")
                
                # Parse response
                success, result = self.parse_dns_response(response_data, transaction_id)
                
                if success:
                    print("✓ Query successful!")
                    for answer in result:
                        print(f"  Answer: {answer}")
                    return True, result, client_rtt
                else:
                    print(f"✗ Query failed: {result}")
                    return False, result, client_rtt
                    
            except socket.timeout:
                print(f"✗ Timeout waiting for response (waited {self.timeout}s)")
                return False, "Timeout", None
                
            except Exception as e:
                print(f"✗ Error receiving response: {e}")
                return False, str(e), None
                
        except Exception as e:
            print(f"✗ Error sending query: {e}")
            return False, str(e), None
            
        finally:
            try:
                sock.close()
            except:
                pass
    
    def run_diagnostics(self):
        """Run comprehensive diagnostics"""
        print("Running DNS Client Diagnostics")
        print("=" * 50)
        
        # Test connectivity
        self.test_connectivity()
        
        # Test with multiple domains and types
        test_cases = [
            ("google.com", "A"),
            ("cloudflare.com", "A"),
        ]
        
        # Add your domain if provided
        if len(sys.argv) > 1:
            test_domain = sys.argv[1]
            test_type = sys.argv[2] if len(sys.argv) > 2 else "A"
            test_cases.insert(0, (test_domain, test_type))
        
        success_count = 0
        for domain, qtype in test_cases:
            success, result, rtt = self.query_dns(domain, qtype)
            if success:
                success_count += 1
            time.sleep(1)  # Small delay between tests
        
        print(f"\n{'='*50}")
        print(f"Diagnostics Summary: {success_count}/{len(test_cases)} tests passed")
        print(f"{'='*50}")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 dns_client_debug.py <domain> [query_type]")
        print("  python3 dns_client_debug.py --diagnostics")
        print("\nExamples:")
        print("  python3 dns_client_debug.py google.com A")
        print("  python3 dns_client_debug.py yourdomain.com NS")
        print("  python3 dns_client_debug.py --diagnostics")
        return
    
    # Create client
    client = DNSClient()
    
    if sys.argv[1] == "--diagnostics":
        client.run_diagnostics()
    else:
        domain = sys.argv[1]
        query_type = sys.argv[2] if len(sys.argv) > 2 else "A"
        
        # Test connectivity first
        client.test_connectivity()
        
        # Run query
        success, result, client_rtt = client.query_dns(domain, query_type)
        
        if not success:
            print("\nTroubleshooting suggestions:")
            print("1. Check if proxy is running on 10.230.3.85:53")
            print("2. Check firewall rules on proxy machine")
            print("3. Verify proxy is forwarding to recursive resolver")
            print("4. Check recursive resolver logs for errors")
            print("5. Try querying recursive resolver directly:")
            print(f"   dig @10.230.3.83 {domain} {query_type}")

if __name__ == "__main__":
    main()
