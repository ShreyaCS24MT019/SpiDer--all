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

class EncryptedANSServer:
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
            
            print("ANS encryption keys loaded successfully")
            
        except Exception as e:
            print(f"Error loading keys: {e}")
            sys.exit(1)
    
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
            print("RR signature verified")
            
            # Decrypt DNS data
            cipher = Fernet(session_key)
            decrypted_dns = cipher.decrypt(encrypted_dns_data)
            
            return decrypted_dns
            
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def encrypt_for_rr(self, dns_response):
        """Encrypt response for RR"""
        try:
            # Generate session key
            session_key = Fernet.generate_key()
            cipher = Fernet(session_key)
            
            # Encrypt DNS response
            encrypted_data = cipher.encrypt(dns_response)
            
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
            
            response_packet = {
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
                'signature': base64.b64encode(signature).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'timestamp': int(time.time())
            }
            
            return json.dumps(response_packet)
            
        except Exception as e:
            print(f"Encryption error: {e}")
            return None
    
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
        """Handle encrypted request from RR"""
        try:
            # TIMING: Record ANS start time
            ans_start_time = time.time()
            print(f"Encrypted connection from RR: {addr}")
           
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
            
            # Receive packet
            data_len = struct.unpack('!I', recv_exact(conn, 4))[0]
            encrypted_data = recv_exact(conn, data_len).decode()
            print(f"Received {data_len} bytes from RR")
            print("=" * 60)
            print("RECEIVED ENCRYPTED PACKET FROM RR:")
            print("=" * 60)
            print(f"Raw JSON (first 100 chars): {encrypted_data[:100]}...")
            print(f"Total JSON size: {len(encrypted_data)} bytes")
            print("=" * 60)
                       
            # Decrypt DNS query
            decrypted_dns = self.decrypt_from_rr(encrypted_data)
            if not decrypted_dns:
                print("Failed to decrypt from RR")
                return
            
            print(f"Decrypted DNS query ({len(decrypted_dns)} bytes)")
            print("DECRYPTED DNS FROM RR:")
            print(f"   Raw bytes (hex): {decrypted_dns.hex()}")
            print(f"   ASCII view: {decrypted_dns.decode('utf-8', errors='ignore')}")
            print("=" * 60)
            
            # Forward to ANS
            ans_response = self.forward_to_ans(decrypted_dns)
            if not ans_response:
                print("No response from ANS")
                return
            
            # Encrypt response for RR
            encrypted_response = self.encrypt_for_rr(ans_response)
            if not encrypted_response:
                print("Failed to encrypt response")
                return
            
            # Send back to RR
            response_bytes = encrypted_response.encode()
            conn.send(struct.pack('!I', len(response_bytes)))
            conn.send(response_bytes)
            
            # TIMING: Record ANS end time and calculate RTT
            ans_end_time = time.time()
            ans_rtt = (ans_end_time - ans_start_time) * 1000
            print(f"ANS RTT: {ans_rtt:.2f}ms")
            print("Encrypted response sent back to RR")
            
        except Exception as e:
            print(f"Error handling RR request: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
    
    def start_server(self):
        """Start encrypted ANS server"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.listen_port))
            server_socket.listen(10)
            
            print(f"Encrypted ANS Server listening on port {self.listen_port}")
            print(f"Forwarding to ANS on port {self.ans_port}")
            print("Ready for encrypted queries from RR!")
            
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
