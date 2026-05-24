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
from cryptography.hazmat.backends import default_backend
import time

class EncryptedANSServer:
    def __init__(self, listen_port=5354, ans_port=53):
        self.listen_port = listen_port
        self.ans_port = ans_port
        self.load_keys()
        
    def load_keys(self):
        """Load ANS keys for 2-layer asymmetric encryption"""
        try:
            # Load ANS private key (for decryption and signing)
            with open('/etc/powerdns/ans_private_key.pem', 'rb') as f:
                self.ans_private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            # Load RR public key (for verifying RR signatures and encrypting responses to RR)
            with open('/etc/powerdns/recursor_public_key.pem', 'rb') as f:
                self.rr_public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
            
            print(" ANS 2-layer encryption keys loaded successfully")
            
        except Exception as e:
            print(f" Error loading keys: {e}")
            sys.exit(1)
    
    def decrypt_rsa_chunked(self, encrypted_data):
        """Decrypts RSA-encrypted data split into multiple 2-byte length-prefixed chunks."""
        decrypted_chunks = []
        offset = 0
        try:
            while offset < len(encrypted_data):
                if offset + 2 > len(encrypted_data):
                    print(" Malformed chunked RSA: missing length header")
                    return None
                chunk_len = struct.unpack('!H', encrypted_data[offset:offset + 2])[0]
                offset += 2
                if offset + chunk_len > len(encrypted_data):
                    print(" Malformed chunked RSA: incomplete chunk")
                    return None
                encrypted_chunk = encrypted_data[offset:offset + chunk_len]
                offset += chunk_len

                decrypted_chunk = self.ans_private_key.decrypt(
                    encrypted_chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_chunks.append(decrypted_chunk)
            return b''.join(decrypted_chunks)
        except Exception as e:
            print(f" RSA chunk decryption failed: {e}")
            return None

    def decrypt_from_rr(self, encrypted_data):
        """Decrypt 2-layer encrypted packet from RR using pure asymmetric encryption"""
        try:
            print(f" Starting packet decryption from RR, data length: {len(encrypted_data)} bytes")
            
            # Layer 1: Decrypt confidentiality layer using chunked RSA decryption with ANS private key
            print(" Layer 1: Decrypting confidentiality layer (chunked RSA)...")
            signed_data = self.decrypt_rsa_chunked(encrypted_data)
            if signed_data is None:
                print(" Failed to decrypt confidentiality layer")
                return None
            
            print(f" Confidentiality layer decrypted, signed data length: {len(signed_data)} bytes")
            
            # Layer 2: Split signed data and verify RR signature
            print(" Layer 2: Verifying authentication layer...")
            parts = signed_data.split(b'|||SIGNATURE|||')
            if len(parts) != 2:
                print(" Invalid signed data format - signature delimiter not found")
                return None
            
            original_dns_data = parts[0]
            signature = parts[1]
            
            print(f" Original DNS data: {len(original_dns_data)} bytes")
            print(f" Signature: {len(signature)} bytes")
            
            # Verify RR signature using RR public key
            try:
                self.rr_public_key.verify(
                    signature,
                    original_dns_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(" RR signature verified successfully")
            except Exception as e:
                print(f" RR signature verification failed: {e}")
                return None
            
            print(f" Packet decryption completed successfully!")
            return original_dns_data
            
        except Exception as e:
            print(f" Decryption from RR failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def encrypt_for_rr(self, dns_response):
        """Encrypt response for RR using 2-layer asymmetric encryption"""
        try:
            print(" Starting 2-layer encryption for RR...")
            
            # Layer 1: Create signature with ANS private key (authentication)
            signature = self.ans_private_key.sign(
                dns_response,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print(f" Layer 1 (Authentication): Created signature ({len(signature)} bytes)")
            
            # Combine response with signature using same format
            signed_response = dns_response + b'|||SIGNATURE|||' + signature
            
            # Layer 2: Encrypt with RR public key (confidentiality) - chunked RSA
            print(" Layer 2: Encrypting with RR public key...")
            key_size = self.rr_public_key.key_size // 8
            max_chunk_size = key_size - 2 * hashes.SHA256().digest_size - 2  # OAEP padding overhead

            encrypted_chunks = []
            for i in range(0, len(signed_response), max_chunk_size):
                chunk = signed_response[i:i + max_chunk_size]
                encrypted_chunk = self.rr_public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                chunk_len = struct.pack('!H', len(encrypted_chunk))
                encrypted_chunks.append(chunk_len + encrypted_chunk)

            encrypted_response = b''.join(encrypted_chunks)
            
            print(f" Layer 2 (Confidentiality): Encrypted response ({len(encrypted_response)} bytes)")
            print(" 2-layer encryption completed!")
            
            return encrypted_response
            
        except Exception as e:
            print(f" Encryption for RR failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def forward_to_ans(self, dns_packet):
        """Forward to actual ANS (your custom ANS)"""
        try:
            # TIMING: Record start time for ANS query
            ans_query_start_time = time.time()
            
            dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_socket.settimeout(30)
            print(f" Forwarding to ANS on port {self.ans_port}...")
            dns_socket.sendto(dns_packet, ('127.0.0.1', 53))  
            response, _ = dns_socket.recvfrom(512)
            dns_socket.close()
            
            # TIMING: Record end time and calculate ANS query RTT
            ans_query_end_time = time.time()
            ans_query_rtt = (ans_query_end_time - ans_query_start_time) * 1000
            print(f"ANS QUERY RTT: {ans_query_rtt:.2f}ms")
            print(f" Received {len(response)} bytes from ANS")
            return response
        except Exception as e:
            print(f" ANS communication error: {e}")
            try:
                print(" Trying Google DNS fallback...")
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
                print(" Google DNS worked")
                return response
            except Exception as e2:
                print(f" Google DNS also failed: {e2}")
                return None
    
    def handle_encrypted_request(self, conn, addr):
        """Handle encrypted request from RR using 2-layer asymmetric encryption"""
        try:
            # TIMING: Record ANS start time
            ans_start_time = time.time()
            print(f" Encrypted connection from RR: {addr}")
           
            # Helper function to receive exact number of bytes
            def recv_exact(sock, n):
                data = b''
                while len(data) < n:
                    try:
                        packet = sock.recv(n - len(data))
                        if not packet:
                            raise ConnectionError(f"Connection closed while expecting {n} bytes")
                        data += packet
                        print(f" Received {len(packet)} bytes, total: {len(data)}/{n}")
                    except socket.timeout:
                        raise ConnectionError(f"Timeout while receiving {n} bytes")
                return data
            
            conn.settimeout(60)
            
            # Receive encrypted packet length
            print(" Reading packet length...")
            packet_len_data = recv_exact(conn, 4)
            packet_len = struct.unpack('!I', packet_len_data)[0]
            print(f" Packet length: {packet_len} bytes")
            
            if packet_len > 50_000_000:  # Sanity check
                raise ValueError(f"Packet length too large: {packet_len}")
            
            # Receive encrypted packet (raw encrypted data from RR)
            encrypted_data = recv_exact(conn, packet_len)
            
            # TW13: ANS received encrypted query from RR
            print(f"TIMESTAMP: {time.time():.6f} - TW13 received encrypted query from RR")
            
            print(f" Received {packet_len} bytes from RR")
            print("=" * 60)
            print(" RECEIVED ENCRYPTED PACKET FROM RR:")
            print("=" * 60)
            print(f" Encrypted Data (first 100 bytes): {encrypted_data[:100]}...")
            print(f" Total packet size: {len(encrypted_data)} bytes")
            print("=" * 60)
                       
            # TW14: Starting decryption
            print(f"TIMESTAMP: {time.time():.6f} - TW14 starting the decrypting query")
            
            # Decrypt DNS query using 2-layer asymmetric decryption
            decrypted_dns = self.decrypt_from_rr(encrypted_data)
            if not decrypted_dns:
                print(" Failed to decrypt from RR")
                return
            
            # TW15: Ending decryption
            print(f"TIMESTAMP: {time.time():.6f} - TW15 ending the decryption of query")
            
            print(f" Decrypted DNS query ({len(decrypted_dns)} bytes)")
            print(" DECRYPTED DNS FROM RR:")
            print(f"   Raw bytes (hex): {decrypted_dns.hex()}")
            print(f"   ASCII view: {decrypted_dns.decode('utf-8', errors='ignore')}")
            print("=" * 60)
            
            # Forward to ANS
            print(" Forwarding to ANS...")
            ans_response = self.forward_to_ans(decrypted_dns)
            if not ans_response:
                print(" No response from ANS")
                return
            
            # TW16: Encryption started at ANS
            print(f"TIMESTAMP: {time.time():.6f} - TW16 encryption started at ANS")
            
            # Encrypt response for RR using 2-layer asymmetric encryption
            encrypted_response = self.encrypt_for_rr(ans_response)
            if not encrypted_response:
                print(" Failed to encrypt response")
                return
            
            # TW17: Encryption ends at ANS
            print(f"TIMESTAMP: {time.time():.6f} - TW17 encryption ends at ANS")
            
            # Send back to RR
            print(" Sending encrypted response back to RR...")
            conn.send(struct.pack('!I', len(encrypted_response)))
            conn.send(encrypted_response)
            
            # TW18: Sending back the response to RR
            print(f"TIMESTAMP: {time.time():.6f} - TW18 sending back the response to RR")
            
            # TIMING: Record ANS end time and calculate RTT
            ans_end_time = time.time()
            ans_rtt = (ans_end_time - ans_start_time) * 1000
            print(f"ANS RTT: {ans_rtt:.2f}ms")
            print(" Encrypted response sent back to RR")
            
        except Exception as e:
            print(f" Error handling RR request: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
    
    def start_server(self):
        """Start encrypted ANS server with 2-layer asymmetric encryption"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.listen_port))
            server_socket.listen(10)
            
            print("=== 2-Layer Asymmetric Encrypted ANS Server ===")
            print("Layer 1: Authentication (RSA Digital Signatures)")
            print("Layer 2: Confidentiality (RSA Encryption)")
            print("================================================")
            print(f" Encrypted ANS Server listening on port {self.listen_port}")
            print(f" Forwarding to ANS on port {self.ans_port}")
            print(" Ready for encrypted queries from RR!")
            
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
                    print("\n ANS server stopped")
                    break
                except Exception as e:
                    print(f" Error accepting connection: {e}")
                    
        except Exception as e:
            print(f" Error starting ANS server: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass

if __name__ == "__main__":
    server = EncryptedANSServer()
    server.start_server()
