#!/usr/bin/env python3
import socket, threading, struct, time, json, base64

class SimpleANSServer:
    def __init__(self, listen_port=5354, ans_port=53):
        self.listen_port = listen_port
        self.ans_port = ans_port

    def forward_to_ans(self, dns_packet):
        try:
            start = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(dns_packet, ('127.0.0.1', 53))
            response, _ = s.recvfrom(512)
            s.close()
            print(f"ANS QUERY RTT: {(time.time() - start)*1000:.2f}ms")
            return response
        except:
            try:
                start = time.time()
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(5)
                s.sendto(dns_packet, ('8.8.8.8', 53))
                response, _ = s.recvfrom(512)
                s.close()
                print(f"GOOGLE DNS RTT: {(time.time() - start)*1000:.2f}ms")
                return response
            except Exception as e:
                print(f"❌ DNS resolution failed: {e}")
                return None

    def handle_request(self, conn, addr):
        try:
            start_time = time.time()
            print(f"\nTIMESTAMP: {start_time:.6f} - TW12 ANS RECEIVES PACKET FROM RR")
            conn.settimeout(10)

            dns_len_data = conn.recv(2)
            if len(dns_len_data) != 2:
                return
            dns_len = struct.unpack('!H', dns_len_data)[0]
            dns_packet = conn.recv(dns_len)

            print(f"TIMESTAMP: {time.time():.6f} - TW13 received query from RR (NO ENCRYPTION)")
            print(f"TIMESTAMP: {time.time():.6f} - TW14 starting processing query (NO ENCRYPTION)")

            ans_response = self.forward_to_ans(dns_packet)
            if not ans_response:
                return

            print(f"TIMESTAMP: {time.time():.6f} - TW15 ending processing of query (NO ENCRYPTION)")
            print(f"TIMESTAMP: {time.time():.6f} - TW16 response preparation started at ANS (NO ENCRYPTION)")
            print(f"TIMESTAMP: {time.time():.6f} - TW17 response preparation ends at ANS (NO ENCRYPTION)")
            print(f"TIMESTAMP: {time.time():.6f} - TW18 sending back the response to RR (NO ENCRYPTION)")

            conn.send(struct.pack('!H', len(ans_response)))
            conn.send(ans_response)
            print(f"🎉 Response sent (ANS RTT: {(time.time() - start_time)*1000:.2f}ms)")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            conn.close()

    def start_server(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', self.listen_port))
            s.listen(10)
            print(f"🔓 ANS Server (NO ENCRYPTION) listening on port {self.listen_port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_request, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("Server stopped.")
        finally:
            s.close()

if __name__ == "__main__":
    SimpleANSServer().start_server()
