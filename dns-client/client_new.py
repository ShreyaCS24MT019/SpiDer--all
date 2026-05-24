#!/usr/bin/env python3
"""
DNS Client with Embedded Timing in DNS Packets
Sends DNS queries with timing data embedded in Additional Section
"""

import socket
import struct
import sys
import time
import json
from datetime import datetime

class DNSClientWithTiming:
    def __init__(self, proxy_ip="10.230.3.85", proxy_port=53):
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.timeout = 15  # Increased for encryption processing
        
    def encode_domain_name(self, domain):
        """Encode domain name in DNS format"""
        encoded = b''
        for part in domain.split('.'):
            if len(part) > 63:
                raise ValueError(f"Domain part too long: {part}")
            encoded += struct.pack('!B', len(part)) + part.encode('ascii')
        encoded += b'\x00'  # End of name
        return encoded
    
    def create_timing_record(self, timing_data):
        """Create a TXT record containing timing data in Additional Section"""
        # Name: _timing.roydns (our custom marker for this DNS chain)
        name = self.encode_domain_name("_timing.roydns")
        
        # Type: TXT (16), Class: IN (1), TTL: 0
        record_type = 16  # TXT
        record_class = 1  # IN
        ttl = 0
        
        # Create compact timing format - only include essential data
        compact_timing = {
            "id": timing_data.get("query_id", 0),
            "domain": timing_data.get("metadata", {}).get("domain", ""),
            "custom": timing_data.get("metadata", {}).get("is_custom_domain", False),
            "f": {},  # forward path
            "r": {}   # response path
        }
        
        # Add only non-null timestamps with compact keys
        forward_map = {
            "T01_client_start": "c1",
            "T02_proxy_recv": "p1", 
            "T03_proxy_encrypt_start": "p2",
            "T04_proxy_encrypt_end": "p3",
            "T05_proxy_send_to_rr": "p4",
            "T06_rr_recv": "r1",
            "T07_rr_encrypt_start": "r2", 
            "T08_rr_encrypt_end": "r3",
            "T09_rr_send_to_ans": "r4",
            "T10_ans_recv": "a1",
            "T11_ans_encrypt_start": "a2",
            "T12_ans_encrypt_end": "a3",
            "T13_ans_send_response": "a4"
        }
        
        response_map = {
            "T14_rr_recv_response": "r5",
            "T15_rr_decrypt_start": "r6",
            "T16_rr_decrypt_end": "r7", 
            "T17_rr_send_to_proxy": "r8",
            "T18_proxy_recv_response": "p5",
            "T19_proxy_decrypt_start": "p6",
            "T20_proxy_decrypt_end": "p7",
            "T21_proxy_send_to_client": "p8",
            "T22_client_recv": "c2"
        }
        
        # Get start time for offset calculation
        start_time = timing_data.get("forward_path", {}).get("T01_client_start", 0)
        if start_time == 0:
            start_time = time.perf_counter()
        
        # Add forward path timestamps as microsecond offsets
        if "forward_path" in timing_data:
            for long_key, short_key in forward_map.items():
                if timing_data["forward_path"].get(long_key) is not None:
                    if start_time > 0:
                        offset = int((timing_data["forward_path"][long_key] - start_time) * 1000000)
                        compact_timing["f"][short_key] = offset
                    else:
                        compact_timing["f"][short_key] = 0
        
        # Add response path timestamps as microsecond offsets
        if "response_path" in timing_data:
            for long_key, short_key in response_map.items():
                if timing_data["response_path"].get(long_key) is not None:
                    if start_time > 0:
                        offset = int((timing_data["response_path"][long_key] - start_time) * 1000000)
                        compact_timing["r"][short_key] = offset
                    else:
                        compact_timing["r"][short_key] = 0
        
        # Convert to compact JSON
        timing_json = json.dumps(compact_timing, separators=(',', ':'))
        timing_bytes = timing_json.encode('utf-8')
        
        # Check if data fits in single TXT record (max 255 bytes)
        if len(timing_bytes) > 253:  # Leave room for length byte
            print(f"⚠️  Timing data too large ({len(timing_bytes)} bytes), truncating...")
            # Keep only essential forward path data
            compact_timing["f"] = {k: v for k, v in list(compact_timing["f"].items())[:5]}
            compact_timing["r"] = {k: v for k, v in list(compact_timing["r"].items())[:5]}
            timing_json = json.dumps(compact_timing, separators=(',', ':'))
            timing_bytes = timing_json.encode('utf-8')
        
        print(f"📊 Timing record size: {len(timing_bytes)} bytes")
        
        # TXT record format: length byte + data
        txt_data = struct.pack('!B', len(timing_bytes)) + timing_bytes
        rdlength = len(txt_data)
        
        # Assemble the complete record
        record = name + struct.pack('!HHIH', record_type, record_class, ttl, rdlength) + txt_data
        return record
    
    def create_dns_query_with_timing(self, domain, query_type="A"):
        """Create DNS query packet with embedded timing data"""
        print(f"🔨 Creating DNS query for {domain} type {query_type}")
        print(f"🎯 Target: {self.proxy_ip}:{self.proxy_port}")
        
        # 1. CLIENT START TIME
        client_start_time = time.perf_counter()
        
        # Create comprehensive timing data structure for 22-point tracking
        timing_data = {
            "query_id": None,  # Will be set below
            "metadata": {
                "domain": domain,
                "query_type": query_type,
                "client_ip": socket.gethostname(),
                "is_custom_domain": domain.endswith('.roydns.xyz')
            },
            "forward_path": {
                "T01_client_start": client_start_time,
            },
            "response_path": {}
        }
        
        # Transaction ID (random)
        import random
        transaction_id = random.randint(1, 65535)
        timing_data["query_id"] = transaction_id
        
        print(f"🆔 Transaction ID: {transaction_id}")
        print(f"⏱️  T01 - Client Start: {client_start_time:.6f}")
        
        if timing_data["metadata"]["is_custom_domain"]:
            print(f"🔐 Custom domain detected - ANS encryption will be tracked")
        
        # Standard DNS packet construction
        flags = 0x0100  # Standard query
        questions = 1
        answers = 0
        authority = 0
        additional = 1  # For our timing record
        
        # Header: 12 bytes
        header = struct.pack('!HHHHHH', transaction_id, flags, questions, 
                           answers, authority, additional)
        
        # Question section
        qname = self.encode_domain_name(domain)
        type_map = {
            'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'MX': 15, 'TXT': 16, 'AAAA': 28
        }
        qtype = type_map.get(query_type.upper(), 1)
        qclass = 1  # IN (Internet)
        question = qname + struct.pack('!HH', qtype, qclass)
        
        # Create timing record for Additional Section
        timing_record = self.create_timing_record(timing_data)
        
        # Assemble complete query packet
        query = header + question + timing_record
        
        print(f"📦 Query packet size: {len(query)} bytes")
        print(f"🔍 22-point timing data embedded in packet")
        
        return query, transaction_id, timing_data
    
    def extract_timing_from_response(self, response):
        """Extract complete timing data from DNS response"""
        try:
            if len(response) < 12:
                return None, "Response too short"
            
            # Parse header to get counts
            header = struct.unpack('!HHHHHH', response[:12])
            transaction_id, flags, questions, answers, authority, additional = header
            
            print(f"📊 Response sections: Q={questions}, A={answers}, Auth={authority}, Add={additional}")
            
            if additional == 0:
                return None, "No additional section found"
            
            offset = 12
            
            # Skip question section
            for _ in range(questions):
                while offset < len(response) and response[offset] != 0:
                    if response[offset] & 0xC0 == 0xC0:  # Compression
                        offset += 2
                        break
                    else:
                        offset += response[offset] + 1
                if offset < len(response) and response[offset] == 0:
                    offset += 1
                offset += 4  # Skip qtype and qclass
            
            # Skip answer section
            for _ in range(answers):
                if offset < len(response) and response[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += response[offset] + 1
                    if offset < len(response):
                        offset += 1
                
                if offset + 10 > len(response):
                    break
                    
                atype, aclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
                offset += 10 + rdlength
            
            # Skip authority section
            for _ in range(authority):
                if offset < len(response) and response[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += response[offset] + 1
                    if offset < len(response):
                        offset += 1
                
                if offset + 10 > len(response):
                    break
                    
                atype, aclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
                offset += 10 + rdlength
            
            # Parse additional section - look for our timing record
            for _ in range(additional):
                # Parse name
                if offset < len(response) and response[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += response[offset] + 1
                    if offset < len(response):
                        offset += 1
                
                if offset + 10 > len(response):
                    break
                
                atype, aclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
                offset += 10
                
                # Check if this is our timing record (TXT type)
                if atype == 16 and rdlength > 0 and offset + rdlength <= len(response):
                    # Extract TXT data
                    txt_length = response[offset]
                    if txt_length > 0 and offset + 1 + txt_length <= len(response):
                        txt_data = response[offset + 1:offset + 1 + txt_length]
                        try:
                            # Try to parse as JSON
                            timing_json = txt_data.decode('utf-8')
                            compact_timing = json.loads(timing_json)
                            
                            # Check if this is our timing record
                            if 'f' in compact_timing and 'r' in compact_timing:
                                # Expand compact timing back to full format
                                expanded_timing = self.expand_compact_timing(compact_timing)
                                return expanded_timing, "Complete timing data extracted"
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            pass  # Not our timing record, continue
                
                offset += rdlength
            
            return None, "Timing record not found in additional section"
            
        except Exception as e:
            return None, f"Error parsing timing data: {e}"
    
    def expand_compact_timing(self, compact_timing):
        """Expand compact timing format back to full format"""
        try:
            # Reverse mapping
            forward_map = {
                "c1": "T01_client_start",
                "p1": "T02_proxy_recv", 
                "p2": "T03_proxy_encrypt_start",
                "p3": "T04_proxy_encrypt_end",
                "p4": "T05_proxy_send_to_rr",
                "r1": "T06_rr_recv",
                "r2": "T07_rr_encrypt_start", 
                "r3": "T08_rr_encrypt_end",
                "r4": "T09_rr_send_to_ans",
                "a1": "T10_ans_recv",
                "a2": "T11_ans_encrypt_start",
                "a3": "T12_ans_encrypt_end",
                "a4": "T13_ans_send_response"
            }
            
            response_map = {
                "r5": "T14_rr_recv_response",
                "r6": "T15_rr_decrypt_start",
                "r7": "T16_rr_decrypt_end", 
                "r8": "T17_rr_send_to_proxy",
                "p5": "T18_proxy_recv_response",
                "p6": "T19_proxy_decrypt_start",
                "p7": "T20_proxy_decrypt_end",
                "p8": "T21_proxy_send_to_client",
                "c2": "T22_client_recv"
            }
            
            # Reconstruct full timing structure
            expanded = {
                "query_id": compact_timing.get("id", "unknown"),
                "metadata": {
                    "domain": compact_timing.get("domain", "unknown"),
                    "is_custom_domain": compact_timing.get("custom", False)
                },
                "forward_path": {},
                "response_path": {}
            }
            
            # Get current time as reference
            current_time = time.perf_counter()
            
            # Expand forward path
            for short_key, offset_us in compact_timing.get("f", {}).items():
                if short_key in forward_map:
                    long_key = forward_map[short_key]
                    # Convert microsecond offset back to absolute time (approximate)
                    expanded["forward_path"][long_key] = current_time - (offset_us / 1000000.0)
            
            # Expand response path
            for short_key, offset_us in compact_timing.get("r", {}).items():
                if short_key in response_map:
                    long_key = response_map[short_key]
                    expanded["response_path"][long_key] = current_time - (offset_us / 1000000.0)
            
            return expanded
            
        except Exception as e:
            print(f"⚠️  Error expanding compact timing: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def analyze_22_point_timing(self, timing_data):
        """Analyze the complete 22-point timing chain"""
        print(f"\n{'='*80}")
        print(f"🔍 COMPLETE 22-POINT DNS RESOLUTION TIMING ANALYSIS")
        print(f"{'='*80}")
        
        # Add client receive time
        timing_data['response_path']['T22_client_recv'] = time.perf_counter()
        
        try:
            print(f"📋 Query Information:")
            print(f"   🆔 Query ID: {timing_data.get('query_id', 'unknown')}")
            print(f"   🌐 Domain: {timing_data.get('metadata', {}).get('domain', 'unknown')}")
            print(f"   🔐 Custom Domain: {timing_data.get('metadata', {}).get('is_custom_domain', False)}")
            
            # Collect all timestamps
            all_timestamps = {}
            
            # Add forward path timestamps
            forward_path = timing_data.get('forward_path', {})
            for key, value in forward_path.items():
                if value is not None:
                    all_timestamps[key] = value
            
            # Add response path timestamps  
            response_path = timing_data.get('response_path', {})
            for key, value in response_path.items():
                if value is not None:
                    all_timestamps[key] = value
            
            # Sort by timestamp value
            sorted_timestamps = sorted(all_timestamps.items(), key=lambda x: x[1])
            
            if not sorted_timestamps:
                print("❌ No timing data available")
                return
            
            start_time = sorted_timestamps[0][1]  # First timestamp
            
            print(f"\n⏱️  DETAILED TIMING CHAIN:")
            print(f"   {'#':<3} {'Checkpoint':<25} {'Timestamp':<15} {'Δ Total':<12} {'Δ Prev':<12} {'Description':<30}")
            print(f"   {'-'*3} {'-'*25} {'-'*15} {'-'*12} {'-'*12} {'-'*30}")
            
            # Checkpoint descriptions
            descriptions = {
                'T01_client_start': 'Client starts DNS query',
                'T02_proxy_recv': 'Proxy receives query',
                'T03_proxy_encrypt_start': 'Proxy starts encryption',
                'T04_proxy_encrypt_end': 'Proxy ends encryption',
                'T05_proxy_send_to_rr': 'Proxy sends to RR',
                'T06_rr_recv': 'RR receives query',
                'T07_rr_encrypt_start': 'RR starts encryption',
                'T08_rr_encrypt_end': 'RR ends encryption',
                'T09_rr_send_to_ans': 'RR sends to ANS',
                'T10_ans_recv': 'ANS receives query',
                'T11_ans_encrypt_start': 'ANS starts encryption',
                'T12_ans_encrypt_end': 'ANS ends encryption',
                'T13_ans_send_response': 'ANS sends response',
                'T14_rr_recv_response': 'RR receives response',
                'T15_rr_decrypt_start': 'RR starts decryption',
                'T16_rr_decrypt_end': 'RR ends decryption',
                'T17_rr_send_to_proxy': 'RR sends to Proxy',
                'T18_proxy_recv_response': 'Proxy receives response',
                'T19_proxy_decrypt_start': 'Proxy starts decryption',
                'T20_proxy_decrypt_end': 'Proxy ends decryption',
                'T21_proxy_send_to_client': 'Proxy sends to Client',
                'T22_client_recv': 'Client receives response'
            }
            
            prev_time = None
            for i, (checkpoint, timestamp) in enumerate(sorted_timestamps, 1):
                delta_total = (timestamp - start_time) * 1000
                delta_prev = (timestamp - prev_time) * 1000 if prev_time else 0
                description = descriptions.get(checkpoint, 'Unknown checkpoint')
                
                print(f"   {i:<3} {checkpoint:<25} {timestamp:<15.6f} {delta_total:<12.4f}ms {delta_prev:<12.4f}ms {description:<30}")
                prev_time = timestamp
            
            # Calculate specific metrics
            print(f"\n📊 HOP ANALYSIS:")
            
            # Network hops
            if 'T01_client_start' in all_timestamps and 'T02_proxy_recv' in all_timestamps:
                client_to_proxy = (all_timestamps['T02_proxy_recv'] - all_timestamps['T01_client_start']) * 1000
                print(f"   🔗 Client → Proxy Network: {client_to_proxy:.4f}ms")
            
            if 'T05_proxy_send_to_rr' in all_timestamps and 'T06_rr_recv' in all_timestamps:
                proxy_to_rr = (all_timestamps['T06_rr_recv'] - all_timestamps['T05_proxy_send_to_rr']) * 1000
                print(f"   🔗 Proxy → RR Network: {proxy_to_rr:.4f}ms")
            
            if 'T09_rr_send_to_ans' in all_timestamps and 'T10_ans_recv' in all_timestamps:
                rr_to_ans = (all_timestamps['T10_ans_recv'] - all_timestamps['T09_rr_send_to_ans']) * 1000
                print(f"   🔗 RR → ANS Network: {rr_to_ans:.4f}ms")
            
            # Encryption times
            print(f"\n🔐 ENCRYPTION ANALYSIS:")
            
            if 'T03_proxy_encrypt_start' in all_timestamps and 'T04_proxy_encrypt_end' in all_timestamps:
                proxy_encrypt = (all_timestamps['T04_proxy_encrypt_end'] - all_timestamps['T03_proxy_encrypt_start']) * 1000
                print(f"   🔒 Proxy Encryption: {proxy_encrypt:.4f}ms")
            
            if 'T07_rr_encrypt_start' in all_timestamps and 'T08_rr_encrypt_end' in all_timestamps:
                rr_encrypt = (all_timestamps['T08_rr_encrypt_end'] - all_timestamps['T07_rr_encrypt_start']) * 1000
                print(f"   🔒 RR Encryption: {rr_encrypt:.4f}ms")
            
            if 'T11_ans_encrypt_start' in all_timestamps and 'T12_ans_encrypt_end' in all_timestamps:
                ans_encrypt = (all_timestamps['T12_ans_encrypt_end'] - all_timestamps['T11_ans_encrypt_start']) * 1000
                print(f"   🔒 ANS Encryption: {ans_encrypt:.4f}ms")
            
            # Decryption times
            if 'T15_rr_decrypt_start' in all_timestamps and 'T16_rr_decrypt_end' in all_timestamps:
                rr_decrypt = (all_timestamps['T16_rr_decrypt_end'] - all_timestamps['T15_rr_decrypt_start']) * 1000
                print(f"   🔓 RR Decryption: {rr_decrypt:.4f}ms")
            
            if 'T19_proxy_decrypt_start' in all_timestamps and 'T20_proxy_decrypt_end' in all_timestamps:
                proxy_decrypt = (all_timestamps['T20_proxy_decrypt_end'] - all_timestamps['T19_proxy_decrypt_start']) * 1000
                print(f"   🔓 Proxy Decryption: {proxy_decrypt:.4f}ms")
            
            # Total time
            if 'T22_client_recv' in all_timestamps and 'T01_client_start' in all_timestamps:
                total_time = (all_timestamps['T22_client_recv'] - all_timestamps['T01_client_start']) * 1000
                print(f"\n⚡ TOTAL RESOLUTION TIME: {total_time:.4f}ms")
            
        except Exception as e:
            print(f"   ⚠️  Error in timing analysis: {e}")
            import traceback
            traceback.print_exc()
        
        print(f"{'='*80}")
    
    def parse_dns_response(self, response, expected_transaction_id):
        """Parse DNS response packet for actual DNS answers"""
        if len(response) < 12:
            return False, "Response too short"
        
        header = struct.unpack('!HHHHHH', response[:12])
        transaction_id, flags, questions, answers, authority, additional = header
        
        if transaction_id != expected_transaction_id:
            return False, f"Transaction ID mismatch"
        
        rcode = flags & 0x000F
        if rcode != 0:
            response_codes = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
            return False, f"DNS error: {response_codes.get(rcode, f'RCODE_{rcode}')}"
        
        if answers == 0:
            return False, "No answers in response"
        
        # Parse answers (simplified)
        offset = 12
        
        # Skip question section
        for _ in range(questions):
            while offset < len(response) and response[offset] != 0:
                if response[offset] & 0xC0 == 0xC0:
                    offset += 2
                    break
                else:
                    offset += response[offset] + 1
            if offset < len(response) and response[offset] == 0:
                offset += 1
            offset += 4
        
        # Parse answers
        answer_results = []
        for _ in range(answers):
            if offset >= len(response):
                break
                
            # Skip name
            if offset < len(response) and response[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(response) and response[offset] != 0:
                    offset += response[offset] + 1
                if offset < len(response):
                    offset += 1
            
            if offset + 10 > len(response):
                break
                
            atype, aclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
            offset += 10
            
            if offset + rdlength > len(response):
                break
                
            rdata = response[offset:offset+rdlength]
            offset += rdlength
            
            if atype == 1 and rdlength == 4:  # A record
                ip = socket.inet_ntoa(rdata)
                answer_results.append(f"A: {ip}")
        
        return True, answer_results
    
    def query_dns(self, domain, query_type="A"):
        """Send DNS query with 22-point timing tracking"""
        print(f"\n{'='*60}")
        print(f"🚀 DNS Query with 22-Point Timing: {domain} {query_type}")
        print(f"🎯 Target Proxy: {self.proxy_ip}:{self.proxy_port}")
        print(f"{'='*60}")
        
        try:
            # Create query with embedded timing
            query_packet, transaction_id, original_timing = self.create_dns_query_with_timing(domain, query_type)
            
            # Create socket and send
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            print(f"\n📤 Sending query to proxy...")
            bytes_sent = sock.sendto(query_packet, (self.proxy_ip, self.proxy_port))
            print(f"✅ Sent {bytes_sent} bytes with embedded timing data")
            
            print(f"⏳ Waiting for response with complete timing chain...")
            response_data, addr = sock.recvfrom(4096)  # Larger buffer for timing data
            print(f"📥 Received {len(response_data)} bytes from {addr}")
            
            # Extract timing data from response
            response_timing, timing_status = self.extract_timing_from_response(response_data)
            print(f"🔍 Timing extraction: {timing_status}")
            
            # Parse regular DNS response
            success, dns_result = self.parse_dns_response(response_data, transaction_id)
            
            # Analyze complete 22-point timing chain
            if response_timing:
                self.analyze_22_point_timing(response_timing)
            else:
                print(f"⚠️  Only client-side timing available")
                total_time = (time.perf_counter() - original_timing['forward_path']['T01_client_start']) * 1000
                print(f"📊 Total end-to-end time: {total_time:.4f}ms")
            
            if success:
                print(f"\n✅ DNS Resolution Successful!")
                for answer in dns_result:
                    print(f"   📍 {answer}")
                return True, dns_result
            else:
                print(f"\n❌ DNS Resolution Failed: {dns_result}")
                return False, dns_result
                
        except socket.timeout:
            print(f"\n⏰ Timeout after {self.timeout} seconds")
            return False, "Timeout"
        except Exception as e:
            print(f"\n❌ Error: {e}")
            return False, str(e)
        finally:
            try:
                sock.close()
            except:
                pass

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("🔍 DNS Client with 22-Point Timing Analysis")
        print("=" * 50)
        print("Usage:")
        print("  python3 dns_client_timing.py <domain> [query_type]")
        print("\nExamples:")
        print("  python3 dns_client_timing.py google.com A")
        print("  python3 dns_client_timing.py test.roydns.xyz A")
        print("  python3 dns_client_timing.py example.com AAAA")
        print("\nFeatures:")
        print("  • 22-point timing analysis")
        print("  • Encryption/decryption timing")
        print("  • Network hop analysis")
        print("  • Custom domain detection (roydns.xyz)")
        return
    
    domain = sys.argv[1]
    query_type = sys.argv[2] if len(sys.argv) > 2 else "A"
    
    client = DNSClientWithTiming()
    success, result = client.query_dns(domain, query_type)
    
    if not success:
        print(f"\n🔧 Next Steps:")
        print(f"1. Ensure proxy script is modified to handle timing data")
        print(f"2. Ensure RR script adds encryption timing")
        print(f"3. Ensure ANS script adds timing for custom domains")
        print(f"4. Check network connectivity between all components")

if __name__ == "__main__":
    main()
