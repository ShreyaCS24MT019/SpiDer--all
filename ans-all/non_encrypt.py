#!/usr/bin/env python3
import socket
import threading
import struct
import base64
import json
import sys
import os
import subprocess
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.fernet import Fernet
# from cryptography.hazmat.backends import default_backend
import time

class EncryptedANSServer:
    def __init__(self, listen_port=5354, ans_port=53):
        self.listen_port = listen_port
        self.ans_port = ans_port
        # self.load_keys()
        
    def load_keys(self):
        """Load ANS keys for RR communication"""
        # try:
        #     # Load ANS private key
        #     with open('/etc/powerdns/ans_private_key.pem', 'rb') as f:
        #         self.ans_private_key = serialization.load_pem_private_key(
        #             f.read(), password=None, backend=default_backend()
        #         )
        #     
        #     # Load RR public key
        #     with open('/etc/powerdns/rr-to-ans_public_key.pem', 'rb') as f:
        #         self.rr_public_key = serialization.load_pem_public_key(
        #             f.read(), backend=default_backend()
        #         )
        #     
        #     print("ANS encryption keys loaded successfully")
        #     
        # except Exception as e:
        #     print(f"Error loading keys: {e}")
        #     sys.exit(1)
        print("ANS server initialized (NO ENCRYPTION)")
    
    def decrypt_from_rr(self, encrypted_data):
        """Decrypt data from RR"""
        # try:
        #     # TW14: Starting decryption
        #     print(f"TIMESTAMP: {time.time():.6f} - TW14 starting the decrypting query")
        #     
        #     packet = json.loads(encrypted_data)
        #     
        #     # Decrypt session key using ANS private key
        #     session_key = self.ans_private_key.decrypt(
        #         base64.b64decode(packet['encrypted_session_key']),
        #         padding.OAEP(
        #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #             algorithm=hashes.SHA256(),
        #             label=None
        #         )
        #     )
        #     
        #     # Verify signature using RR public key
        #     signature = base64.b64decode(packet['signature'])
        #     encrypted_dns_data = base64.b64decode(packet['encrypted_data'])
        #     
        #     self.rr_public_key.verify(
        #         signature,
        #         encrypted_dns_data,
        #         padding.PSS(
        #             mgf=padding.MGF1(hashes.SHA256()),
        #             salt_length=padding.PSS.MAX_LENGTH
        #         ),
        #         hashes.SHA256()
        #     )
        #     print("RR signature verified")
        #     
        #     # Decrypt DNS data
        #     cipher = Fernet(session_key)
        #     decrypted_dns = cipher.decrypt(encrypted_dns_data)
        #     
        #     # TW15: Ending decryption
        #     print(f"TIMESTAMP: {time.time():.6f} - TW15 ending the decryption of query")
        #     
        #     return decrypted_dns
        #     
        # except Exception as e:
        #     print(f"Decryption error: {e}")
        #     return None
        
        # TW14: Starting processing (no decryption)
        print(f"TIMESTAMP: {time.time():.6f} - TW14 starting the processing query (NO DECRYPTION)")
        
        # For no encryption mode, assume encrypted_data is direct DNS packet in JSON format
        try:
            packet = json.loads(encrypted_data)
            decrypted_dns = base64.b64decode(packet['encrypted_data'])
        except:
            # If not JSON, treat as direct DNS data
            decrypted_dns = encrypted_data.encode() if isinstance(encrypted_data, str) else encrypted_data
        
        # TW15: Ending processing (no decryption)
        print(f"TIMESTAMP: {time.time():.6f} - TW15 ending the processing of query (NO DECRYPTION)")
        print("✅ Data processed successfully (NO DECRYPTION)")
        
        return decrypted_dns
    
    def encrypt_for_rr(self, dns_response):
        """Encrypt response for RR"""
        # try:
        #     # TW16: Encryption started at ANS
        #     print(f"TIMESTAMP: {time.time():.6f} - TW16 encryption started at ANS")
        #     
        #     # Generate session key
        #     session_key = Fernet.generate_key()
        #     cipher = Fernet(session_key)
        #     
        #     # Encrypt DNS response
        #     encrypted_data = cipher.encrypt(dns_response)
        #     
        #     # Sign with ANS private key
        #     signature = self.ans_private_key.sign(
        #         encrypted_data,
        #         padding.PSS(
        #             mgf=padding.MGF1(hashes.SHA256()),
        #             salt_length=padding.PSS.MAX_LENGTH
        #         ),
        #         hashes.SHA256()
        #     )
        #     
        #     # Encrypt session key with RR public key
        #     encrypted_session_key = self.rr_public_key.encrypt(
        #         session_key,
        #         padding.OAEP(
        #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #             algorithm=hashes.SHA256(),
        #             label=None
        #         )
        #     )
        #     
        #     response_packet = {
        #         'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
        #         'signature': base64.b64encode(signature).decode(),
        #         'encrypted_data': base64.b64encode(encrypted_data).decode(),
        #         'timestamp': int(time.time())
        #     }
        #     
        #     # TW17: Encryption ends at ANS
        #     print(f"TIMESTAMP: {time.time():.6f} - TW17 encryption ends at ANS")
        #     
        #     return json.dumps(response_packet)
        #     
        # except Exception as e:
        #     print(f"Encryption error: {e}")
        #     return None
        
        # TW16: Response preparation started at ANS (no encryption)
        print(f"TIMESTAMP: {time.time():.6f} - TW16 response preparation started at ANS (NO ENCRYPTION)")
        
        # Create dummy response packet without encryption
        response_packet = {
            'encrypted_session_key': base64.b64encode(b"dummy_ans_session_key").decode(),
            'signature': base64.b64encode(b"dummy_ans_signature").decode(),
            'encrypted_data': base64.b64encode(dns_response).decode(),
            'timestamp': int(time.time())
        }
        
        # TW17: Response preparation ends at ANS (no encryption)
        print(f"TIMESTAMP: {time.time():.6f} - TW17 response preparation ends at ANS (NO ENCRYPTION)")
        print("✅ Response prepared successfully (NO ENCRYPTION)")
        
        return json.dumps(response_packet)
    
    def forward_to_ans(self, dns_packet):
        """Forward to actual ANS (your custom ANS)"""
        try:
            # TIMING: Record start time for ANS query
            ans_query_start_time = time.time()
            
            dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_socket.settimeout(30)
            print(f"Forwarding to ANS on port {self.ans_port}...")
            dns_socket.sendto(dns_packet, ('127.0.0.1', 53))  # This line fails because PowerDNS is broken
            response, _ = dns_socket.recvfrom(512)
            dns_socket.close()
            
            # TIMING: Record end time and calculate ANS query RTT
            ans_query_end_time = time.time()
            ans_query_rtt = (ans_query_end_time - ans_query_start_time) * 1000
            print(f"ANS QUERY RTT: {ans_query_rtt:.2f}ms")
            print(f"Received {len(response)} bytes from ANS")
            return response
        except Exception as e:
            print(f"ANS communication error: {e}")
            try:
                print("Trying Google DNS...")
                # TIMING: Record start time for Google DNS fallback
                google_start_time = time.time()
                
                dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                dns_socket.settimeout(5)
                dns_socket.sendto(dns_packet, ('8.8.8.8', 53))
                response, _ = dns_socket.recvfrom(512)
                dns_socket.close()
                
                # TIMING: Record end time and calculate Google DNS RTT
                google_end_time = time.time()
                google_rtt = (google_end_time - google_start_time) * 1000
                print(f"GOOGLE DNS RTT: {google_rtt:.2f}ms")
                print("Google DNS worked")
                return response
            except Exception as e2:
                print(f"Google DNS also failed: {e2}")
                return None
    
    def handle_encrypted_request(self, conn, addr):
        """Handle request from RR - matches RR's send_to_ans_direct protocol"""
        try:
            # TIMING: Record ANS start time
            ans_start_time = time.time()
            print(f"TIMESTAMP: {time.time():.6f} - TW12 ANS RECEIVES PACKET FROM RR")
            print(f"Connection from RR: {addr}")
           
            # Set socket timeout
            conn.settimeout(30)
            
            # TW13: ANS received query from RR (no encryption)
            print(f"TIMESTAMP: {time.time():.6f} - TW13 received query from RR (NO ENCRYPTION)")
            
            # Receive DNS packet length and data (matches RR's send_to_ans_direct)
            print("📥 Reading DNS packet length...")
            dns_len_data = conn.recv(2)
            if len(dns_len_data) != 2:
                print("❌ Failed to receive DNS length")
                return
                
            dns_len = struct.unpack('!H', dns_len_data)[0]
            print(f"📥 DNS packet length: {dns_len} bytes")
            
            if dns_len > 10240:  # Sanity check
                raise ValueError(f"DNS packet too large: {dns_len}")
            
            # Receive DNS packet data
            dns_packet = conn.recv(dns_len)
            print(f"✅ DNS packet received ({len(dns_packet)} bytes)")
            
            print("=" * 60)
            print("📦 DNS PACKET FROM RR (NO ENCRYPTION):")
            print("=" * 60)
            print(f"🔍 Raw DNS bytes (hex): {dns_packet.hex()}")
            print(f"🔍 ASCII view: {dns_packet.decode('utf-8', errors='ignore')}")
            print("=" * 60)
            
            # Process DNS packet (no decryption needed)
            print(f"TIMESTAMP: {time.time():.6f} - TW14 starting the processing query (NO DECRYPTION)")
            print("🔓 Processing DNS packet...")
            
            # Forward to authoritative DNS server
            print(f"TIMESTAMP: {time.time():.6f} - TW15 ending the processing of query (NO DECRYPTION)")
            print("📡 Forwarding to authoritative DNS...")
            ans_response = self.forward_to_ans(dns_packet)
            
            if not ans_response:
                print("❌ No response from authoritative DNS")
                return
            
            print(f"✅ Received response from authoritative DNS ({len(ans_response)} bytes)")
            
            # Prepare response (no encryption)
            print(f"TIMESTAMP: {time.time():.6f} - TW16 response preparation started at ANS (NO ENCRYPTION)")
            print("🔒 Preparing response for RR...")
            
            # Send response back to RR (matches RR's expectation)
            print(f"TIMESTAMP: {time.time():.6f} - TW17 response preparation ends at ANS (NO ENCRYPTION)")
            print(f"TIMESTAMP: {time.time():.6f} - TW18 sending back the response to RR (NO ENCRYPTION)")
            print("📤 Sending response to RR...")
            
            # Send response length and data
            response_len = len(ans_response)
            conn.send(struct.pack('!H', response_len))
            conn.send(ans_response)
            
            # TIMING: Record ANS end time and calculate RTT
            ans_end_time = time.time()
            ans_rtt = (ans_end_time - ans_start_time) * 1000
            print(f"ANS RTT: {ans_rtt:.2f}ms")
            print("🎉 DNS response sent successfully!")
            
        except Exception as e:
            print(f"❌ Error handling RR request: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
    
    def start_server(self):
        """Start ANS server"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.listen_port))
            server_socket.listen(10)
            
            print(f"ANS Server listening on port {self.listen_port} (NO ENCRYPTION)")
            print(f"Forwarding to ANS on port {self.ans_port}")
            print("Ready for queries from RR!")
            
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
                    print("\nANS server stopped")
                    break
                except Exception as e:
                    print(f"Error accepting connection: {e}")
                    
        except Exception as e:
            print(f"Error starting ANS server: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass

if __name__ == "__main__":
    server = EncryptedANSServer()
    server.start_server()
