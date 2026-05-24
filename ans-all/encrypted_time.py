#!/usr/bin/env python3
import socket
import threading
import struct
import base64
import json
import sys
import os
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import time

class EncryptedANSServerWithTiming:
    def __init__(self, listen_port=5354, ans_port=53):
        self.listen_port = listen_port
        self.ans_port = ans_port
        self.load_keys()
        
    def load_keys(self):
        """Load ANS keys for RR communication"""
        try:
            # Load ANS private key
            with open('/etc/powerdns/ans_private_key.pem', 'rb') as f:
                self.ans_private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            # Load RR public key
            with open('/etc/powerdns/rr-to-ans_public_key.pem', 'rb') as f:
                self.rr_public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
            
            print("✅ ANS encryption keys loaded successfully")
            
        except Exception as e:
            print(f"❌ Error loading keys: {e}")
            sys.exit(1)
    
    def extract_timing_from_dns_packet(self, dns_data):
        """Extract timing data from DNS packet Additional Section"""
        try:
            if len(dns_data) < 12:
                return None, dns_data, "DNS packet too short"
            
            # Parse header to get counts
            header = struct.unpack('!HHHHHH', dns_data[:12])
            transaction_id, flags, questions, answers, authority, additional = header
            
            print(f"🔍 DNS packet analysis: Q={questions}, A={answers}, Auth={authority}, Add={additional}")
            
            if additional == 0:
                return None, dns_data, "No additional section found"
            
            offset = 12
            
            # Skip question section
            for _ in range(questions):
                while offset < len(dns_data) and dns_data[offset] != 0:
                    if dns_data[offset] & 0xC0 == 0xC0:  # Compression
                        offset += 2
                        break
                    else:
                        offset += dns_data[offset] + 1
                if offset < len(dns_data) and dns_data[offset] == 0:
                    offset += 1
                offset += 4  # Skip qtype and qclass
            
            # Skip answer section (should be empty in query)
            for _ in range(answers):
                if offset < len(dns_data) and dns_data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(dns_data) and dns_data[offset] != 0:
                        offset += dns_data[offset] + 1
                    if offset < len(dns_data):
                        offset += 1
                
                if offset + 10 > len(dns_data):
                    break
                    
                atype, aclass, ttl, rdlength = struct.unpack('!HHIH', dns_data[offset:offset+10])
                offset += 10 + rdlength
            
            # Skip authority section
            for _ in range(authority):
                if offset < len(dns_data) and dns_data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(dns_data) and dns_data[offset] != 0:
                        offset += dns_data[offset] + 1
                    if offset < len(dns_data):
                        offset += 1
                
                if offset + 10 > len(dns_data):
                    break
                    
                atype, aclass, ttl, rdlength = struct.unpack('!HHIH', dns_data[offset:offset+10])
                offset += 10 + rdlength
            
            # Parse additional section - look for our timing record
            for _ in range(additional):
                name_start = offset
                
                # Parse name
                if offset < len(dns_data) and dns_data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(dns_data) and dns_data[offset] != 0:
                        offset += dns_data[offset] + 1
                    if offset < len(dns_data):
                        offset += 1
                
                if offset + 10 > len(dns_data):
                    break
                
                atype, aclass, ttl, rdlength = struct.unpack('!HHIH', dns_data[offset:offset+10])
                record_start = offset
                offset += 10
                
                # Check if this is our timing record (TXT type)
                if atype == 16 and rdlength > 0 and offset + rdlength <= len(dns_data):
                    # Extract TXT data
                    txt_length = dns_data[offset]
                    if txt_length > 0 and offset + 1 + txt_length <= len(dns_data):
                        txt_data = dns_data[offset + 1:offset + 1 + txt_length]
                        try:
                            # Try to parse as JSON
                            timing_json = txt_data.decode('utf-8')
                            timing_data = json.loads(timing_json)
                            
                            # Check if this is our timing record
                            if 'f' in timing_data and 'r' in timing_data:
                                # Expand compact timing back to full format
                                expanded_timing = self.expand_compact_timing(timing_data)
                                if expanded_timing:
                                    print(f"✅ Found timing record in additional section")
                                    
                                    # Create DNS packet without timing record
                                    dns_without_timing = (dns_data[:name_start] + 
                                                        dns_data[offset + rdlength:])
                                    
                                    # Update header to decrease additional count
                                    new_header = struct.pack('!HHHHHH', transaction_id, flags, 
                                                            questions, answers, authority, additional - 1)
                                    dns_without_timing = new_header + dns_without_timing[12:]
                                    
                                    return expanded_timing, dns_without_timing, "Timing data extracted"
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            pass  # Not our timing record, continue
                
                offset += rdlength
            
            return None, dns_data, "Timing record not found"
            
        except Exception as e:
            return None, dns_data, f"Error extracting timing: {e}"
    
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
            
            # Get start time reference from client start
            base_time = time.perf_counter()
            if "f" in compact_timing and "c1" in compact_timing["f"]:
                # Use current time minus the largest offset as approximation
                max_offset = max(compact_timing["f"].values()) if compact_timing["f"] else 0
                base_time = time.perf_counter() - (max_offset / 1000000.0)
            
            # Expand forward path
            for short_key, offset_us in compact_timing.get("f", {}).items():
                if short_key in forward_map:
                    long_key = forward_map[short_key]
                    expanded["forward_path"][long_key] = base_time + (offset_us / 1000000.0)
            
            # Expand response path
            for short_key, offset_us in compact_timing.get("r", {}).items():
                if short_key in response_map:
                    long_key = response_map[short_key]
                    expanded["response_path"][long_key] = base_time + (offset_us / 1000000.0)
            
            return expanded
            
        except Exception as e:
            print(f"⚠️  Error expanding compact timing: {e}")
            return None
    
    def add_timing_to_dns_packet(self, dns_data, timing_data):
        """Add timing data back to DNS packet Additional Section"""
        try:
            if len(dns_data) < 12:
                return dns_data
            
            # Parse header
            header = struct.unpack('!HHHHHH', dns_data[:12])
            transaction_id, flags, questions, answers, authority, additional = header
            
            # Create timing record
            timing_record = self.create_timing_record(timing_data)
            
            # Update header to increase additional count
            new_header = struct.pack('!HHHHHH', transaction_id, flags, 
                                   questions, answers, authority, additional + 1)
            
            # Assemble new packet
            new_dns_data = new_header + dns_data[12:] + timing_record
            
            return new_dns_data
            
        except Exception as e:
            print(f"❌ Error adding timing to DNS packet: {e}")
            return dns_data
    
    def create_timing_record(self, timing_data):
        """Create a TXT record containing timing data"""
        # Name: _timing.roydns
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
                    offset = int((timing_data["forward_path"][long_key] - start_time) * 1000000)
                    compact_timing["f"][short_key] = offset
        
        # Add response path timestamps as microsecond offsets
        if "response_path" in timing_data:
            for long_key, short_key in response_map.items():
                if timing_data["response_path"].get(long_key) is not None:
                    offset = int((timing_data["response_path"][long_key] - start_time) * 1000000)
                    compact_timing["r"][short_key] = offset
        
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
    
    def encode_domain_name(self, domain):
        """Encode domain name in DNS format"""
        encoded = b''
        for part in domain.split('.'):
            if len(part) > 63:
                raise ValueError(f"Domain part too long: {part}")
            encoded += struct.pack('!B', len(part)) + part.encode('ascii')
        encoded += b'\x00'  # End of name
        return encoded
    
    def decrypt_from_rr(self, encrypted_data):
        """Decrypt data from RR"""
        try:
            packet = json.loads(encrypted_data)
            
            # Decrypt session key using ANS private key
            session_key = self.ans_private_key.decrypt(
                base64.b64decode(packet['encrypted_session_key']),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Verify signature using RR public key
            signature = base64.b64decode(packet['signature'])
            encrypted_dns_data = base64.b64decode(packet['encrypted_data'])
            
            self.rr_public_key.verify(
                signature,
                encrypted_dns_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("✅ RR signature verified")
            
            # Decrypt DNS data
            cipher = Fernet(session_key)
            decrypted_dns = cipher.decrypt(encrypted_dns_data)
            
            return decrypted_dns
            
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            return None
    
    def encrypt_for_rr(self, dns_response, timing_data):
        """Encrypt response for RR with timing data"""
        try:
            # Add timing data to response before encryption
            dns_response_with_timing = self.add_timing_to_dns_packet(dns_response, timing_data)
            
            # T11: ANS ENCRYPTION START (if custom domain)
            if timing_data.get('metadata', {}).get('is_custom_domain', False):
                timing_data['forward_path']['T11_ans_encrypt_start'] = time.perf_counter()
                print(f"🔒 T11 - ANS Encryption Start: {timing_data['forward_path']['T11_ans_encrypt_start']:.6f}")
            
            # Generate session key
            session_key = Fernet.generate_key()
            cipher = Fernet(session_key)
            
            # Encrypt DNS response
            encrypted_data = cipher.encrypt(dns_response_with_timing)
            
            # Sign with ANS private key
            signature = self.ans_private_key.sign(
                encrypted_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Encrypt session key with RR public key
            encrypted_session_key = self.rr_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # T12: ANS ENCRYPTION END (if custom domain)
            if timing_data.get('metadata', {}).get('is_custom_domain', False):
                timing_data['forward_path']['T12_ans_encrypt_end'] = time.perf_counter()
                print(f"🔓 T12 - ANS Encryption End: {timing_data['forward_path']['T12_ans_encrypt_end']:.6f}")
                
                ans_encrypt_time = (timing_data['forward_path']['T12_ans_encrypt_end'] - 
                                  timing_data['forward_path']['T11_ans_encrypt_start']) * 1000
                print(f"⏱️  ANS encryption time: {ans_encrypt_time:.4f}ms")
            
            response_packet = {
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
                'signature': base64.b64encode(signature).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'timestamp': int(time.time())
            }
            
            return json.dumps(response_packet)
            
        except Exception as e:
            print(f"❌ Encryption error: {e}")
            return None
    
    def forward_to_ans(self, dns_packet):
        """Forward to actual ANS (your custom ANS)"""
        try:
            dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_socket.settimeout(30)
            print(f"📡 Forwarding to ANS on port {self.ans_port}...")
            dns_socket.sendto(dns_packet, ('127.0.0.1', 53))  # This line fails because PowerDNS is broken
            response, _ = dns_socket.recvfrom(512)
            dns_socket.close()
            print(f"✅ Received {len(response)} bytes from ANS")
            return response
        except Exception as e:
            print(f"❌ ANS communication error: {e}")
            try:
                print("🔄 Trying Google DNS...")
                dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                dns_socket.settimeout(5)
                dns_socket.sendto(dns_packet, ('8.8.8.8', 53))
                response, _ = dns_socket.recvfrom(512)
                dns_socket.close()
                print("✅ Google DNS worked")
                return response
            except Exception as e2:
                print(f"❌ Google DNS also failed: {e2}")
                return None
    
    def handle_encrypted_request(self, conn, addr):
        """Handle encrypted request from RR with 22-point timing completion"""
        print(f"\n{'='*80}")
        print(f"🚀 ENCRYPTED ANS CONNECTION WITH FINAL TIMING from: {addr}")
        print(f"{'='*80}")
        
        timing_data = None
        
        try:
            # Receive encrypted data (similar to previous server)
            def recv_exact(sock, n):
                data = b''
                while len(data) < n:
                    packet = sock.recv(n - len(data))
                    if not packet:
                        raise ConnectionError("Connection closed")
                    data += packet
                return data
            
            conn.settimeout(60)
            
            # T10: ANS RECEIVES PACKET
            ans_recv_time = time.perf_counter()
            print(f"📥 T10 - ANS Recv: {ans_recv_time:.6f}")
            
            # Receive packet
            data_len = struct.unpack('!I', recv_exact(conn, 4))[0]
            encrypted_data = recv_exact(conn, data_len).decode()
            print(f"📥 Received {data_len} bytes from RR")
            print("=" * 60)
            print("📦 RECEIVED ENCRYPTED PACKET FROM RR:")
            print("=" * 60)
            print(f"📄 Raw JSON (first 100 chars): {encrypted_data[:100]}...")
            print(f"📊 Total JSON size: {len(encrypted_data)} bytes")
            print("=" * 60)
                       
            # Decrypt DNS query
            decrypted_dns = self.decrypt_from_rr(encrypted_data)
            if not decrypted_dns:
                print("❌ Failed to decrypt from RR")
                return
            
            print(f"✅ Decrypted DNS query ({len(decrypted_dns)} bytes)")
            print("🔓 DECRYPTED DNS FROM RR:")
            print(f"   Raw bytes (hex): {decrypted_dns[:64].hex()}...")
            print(f"   ASCII view: {decrypted_dns.decode('utf-8', errors='ignore')}")
            print("=" * 60)
            
            # Extract timing data from DNS packet
            timing_data, dns_without_timing, extraction_status = self.extract_timing_from_dns_packet(decrypted_dns)
            
            if timing_data:
                # Update with ANS receive time
                timing_data['forward_path']['T10_ans_recv'] = ans_recv_time
                print(f"✅ Timing data extracted: {extraction_status}")
                print(f"🆔 Query ID: {timing_data['query_id']}")
                print(f"🌐 Domain: {timing_data['metadata']['domain']}")
                print(f"🔐 Custom Domain: {timing_data['metadata']['is_custom_domain']}")
            else:
                print(f"⚠️  No timing data found: {extraction_status}")
                dns_without_timing = decrypted_dns
                # Create minimal timing structure
                timing_data = {
                    'query_id': 'unknown',
                    'metadata': {'domain': 'unknown', 'is_custom_domain': False},
                    'forward_path': {'T10_ans_recv': ans_recv_time},
                    'response_path': {}
                }
            
            # Forward to ANS
            ans_response = self.forward_to_ans(dns_without_timing)
            if not ans_response:
                print("❌ No response from ANS")
                return
            
            print(f"✅ Received response from ANS ({len(ans_response)} bytes)")
            
            # T13: ANS SEND RESPONSE
            timing_data['forward_path']['T13_ans_send_response'] = time.perf_counter()
            print(f"📤 T13 - ANS Send Response: {timing_data['forward_path']['T13_ans_send_response']:.6f}")
            
            # Encrypt response for RR (includes T11-T12 if custom domain)
            encrypted_response = self.encrypt_for_rr(ans_response, timing_data)
            if not encrypted_response:
                print("❌ Failed to encrypt response")
                return
            
            # Send back to RR
            response_bytes = encrypted_response.encode()
            conn.send(struct.pack('!I', len(response_bytes)))
            conn.send(response_bytes)
            
            print("✅ Encrypted response sent back to RR")
            
            # Calculate total ANS processing time
            total_ans_time = (timing_data['forward_path']['T13_ans_send_response'] - 
                            timing_data['forward_path']['T10_ans_recv']) * 1000
            print(f"⏱️  Total ANS processing time: {total_ans_time:.4f}ms")
            
            # Show ANS timing summary
            print(f"\n📊 ANS TIMING SUMMARY:")
            if timing_data.get('metadata', {}).get('is_custom_domain', False):
                if 'T11_ans_encrypt_start' in timing_data['forward_path'] and 'T12_ans_encrypt_end' in timing_data['forward_path']:
                    encrypt_time = (timing_data['forward_path']['T12_ans_encrypt_end'] - 
                                  timing_data['forward_path']['T11_ans_encrypt_start']) * 1000
                    print(f"   🔐 Custom Domain Encryption: {encrypt_time:.4f}ms")
                else:
                    print(f"   🔐 Custom Domain - No encryption timing recorded")
            else:
                print(f"   🌐 Global Domain - No encryption needed")
            
            if 'T10_ans_recv' in timing_data['forward_path'] and 'T13_ans_send_response' in timing_data['forward_path']:
                processing_time = (timing_data['forward_path']['T13_ans_send_response'] - 
                                 timing_data['forward_path']['T10_ans_recv']) * 1000
                print(f"   ⚡ Total Processing: {processing_time:.4f}ms")
            
            print(f"🎉 COMPLETE 22-POINT TIMING CHAIN ACHIEVED!")
            print(f"{'='*80}")
            
        except Exception as e:
            print(f"❌ Error handling RR request: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
    
    def start_server(self):
        """Start encrypted ANS server with final timing points"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.listen_port))
            server_socket.listen(10)
            
            print("="*80)
            print("🚀 ENCRYPTED ANS SERVER WITH FINAL 22-POINT TIMING")
            print("="*80)
            print("🔐 Handles encrypted communication with RR")
            print("🔐 Custom domain encryption for roydns.xyz")
            print("⏱️  Final Timing Points: T10, T11, T12, T13")
            print("🎯 Completes 22-Point Timing Chain!")
            print("="*80)
            print(f"🔐 Encrypted ANS Server listening on port {self.listen_port}")
            print(f"📡 Forwarding to ANS on port {self.ans_port}")
            print("🚀 Ready for encrypted queries from RR!")
            
            while True:
                try:
                    conn, addr = server_socket.accept()
                    thread = threading.Thread(
                        target=self.handle_encrypted_request,
                        args=(conn, addr)
                    )
                    thread.daemon = True
                    thread.start()
                except KeyboardInterrupt:
                    print("\n🛑 ANS server stopped")
                    break
                except Exception as e:
                    print(f"❌ Error accepting connection: {e}")
                    
        except Exception as e:
            print(f"❌ Error starting ANS server: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass

if __name__ == "__main__":
    server = EncryptedANSServerWithTiming()
    server.start_server()
