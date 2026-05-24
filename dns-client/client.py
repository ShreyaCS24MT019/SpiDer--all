import socket
import struct
import random

def create_dns_query(domain, query_type=1):
    """Create a DNS query packet"""
    # Transaction ID (2 bytes)
    transaction_id = random.randint(0, 65535)
    
    # Flags (2 bytes) - Standard query
    flags = 0x0100  # Recursion desired
    
    # Questions count (2 bytes)
    questions = 1
    
    # Answer RRs, Authority RRs, Additional RRs (2 bytes each)
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0
    
    # DNS Header
    header = struct.pack('!HHHHHH', transaction_id, flags, questions, 
                        answer_rrs, authority_rrs, additional_rrs)
    
    # Question section
    question = b''
    for part in domain.split('.'):
        question += struct.pack('!B', len(part)) + part.encode()
    question += b'\x00'  # End of domain name
    question += struct.pack('!HH', query_type, 1)  # Type A, Class IN
    
    return header + question

def parse_dns_response(response):
    """Parse DNS response packet"""
    if len(response) < 12:
        return "Invalid DNS response"
    
    # Parse header
    header = struct.unpack('!HHHHHH', response[:12])
    transaction_id, flags, questions, answers, authority, additional = header
    
    # Check if response bit is set
    if not (flags & 0x8000):
        return "Not a DNS response"
    
    # Extract IP addresses from answer section
    if answers == 0:
        return "No answers found"
    
    # Simple parsing - look for A records (IPv4 addresses)
    ips = []
    pos = 12
    
    # Skip question section
    try:
        while pos < len(response) and response[pos] != 0:
            length = response[pos]
            pos += length + 1
        pos += 5  # Skip null terminator and type/class
        
        # Parse answer section
        for _ in range(answers):
            if pos + 12 > len(response):
                break
            
            # Skip name (assume compression)
            if response[pos] & 0xC0:
                pos += 2
            else:
                while pos < len(response) and response[pos] != 0:
                    pos += response[pos] + 1
                pos += 1
            
            # Read type, class, ttl, data length
            if pos + 10 > len(response):
                break
            
            record_type, record_class, ttl, data_length = struct.unpack('!HHIH', response[pos:pos+10])
            pos += 10
            
            # If it's an A record (type 1) and data length is 4
            if record_type == 1 and data_length == 4 and pos + 4 <= len(response):
                ip = socket.inet_ntoa(response[pos:pos+4])
                ips.append(ip)
            
            pos += data_length
    
    except:
        return "Error parsing DNS response"
    
    return ips if ips else "No IP addresses found"

def client():
    # Proxy server details (DNS proxy)
    PROXY_HOST = '10.230.3.85'
    PROXY_PORT = 8080
    
    try:
        # Create UDP socket for DNS
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.settimeout(10)  # 10 second timeout
        
        print(f"DNS Client ready. Proxy server: {PROXY_HOST}:{PROXY_PORT}")
        
        while True:
            # Get domain name from user
            domain = input("\nEnter domain name to resolve (or 'quit' to exit): ").strip()
            
            if domain.lower() == 'quit':
                break
            
            if not domain:
                continue
            
            # Create DNS query
            dns_query = create_dns_query(domain)
            print(f"Resolving: {domain}")
            
            # Send DNS query to proxy
            client_socket.sendto(dns_query, (PROXY_HOST, PROXY_PORT))
            
            try:
                # Receive DNS response from proxy
                response, addr = client_socket.recvfrom(512)
                print(f"Received response from: {addr}")
                
                # Parse and display result
                result = parse_dns_response(response)
                if isinstance(result, list):
                    print(f"IP addresses for {domain}:")
                    for ip in result:
                        print(f"  {ip}")
                else:
                    print(f"Result: {result}")
                    
            except socket.timeout:
                print("Timeout waiting for response")
            except Exception as e:
                print(f"Error receiving response: {e}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("DNS Client disconnected.")

if __name__ == "__main__":
    client()
