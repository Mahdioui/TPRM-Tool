"""
Sample PCAP Generator - Create sample network traffic for testing
Generates realistic network traffic patterns for demonstration purposes
"""

import os
import time
import random
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR

def generate_sample_pcap(filename="sample_traffic.pcap", packet_count=1000):
    """
    Generate a sample PCAP file with various types of network traffic
    
    Args:
        filename: Output PCAP filename
        packet_count: Number of packets to generate
    """
    packets = []
    
    # Define some realistic IP addresses
    internal_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.15"]
    external_ips = ["8.8.8.8", "1.1.1.1", "172.217.12.174", "151.101.193.140"]
    suspicious_ips = ["185.220.101.32", "194.87.94.50"]  # Known malicious IPs
    
    # Web servers and domains
    web_servers = {
        "172.217.12.174": "google.com",
        "151.101.193.140": "reddit.com", 
        "104.16.123.96": "example.com"
    }
    
    print(f"Generating {packet_count} packets...")
    
    for i in range(packet_count):
        # Vary the traffic types
        traffic_type = random.choices(
            ["http", "dns", "suspicious", "normal_tcp", "icmp", "malware"],
            weights=[30, 20, 5, 25, 15, 5],
            k=1
        )[0]
        
        src_ip = random.choice(internal_ips)
        
        if traffic_type == "http":
            # Generate HTTP traffic
            dst_ip = random.choice(list(web_servers.keys()))
            packets.extend(generate_http_traffic(src_ip, dst_ip, web_servers[dst_ip]))
            
        elif traffic_type == "dns":
            # Generate DNS queries
            dst_ip = random.choice(external_ips)
            packets.extend(generate_dns_traffic(src_ip, dst_ip))
            
        elif traffic_type == "suspicious":
            # Generate suspicious traffic
            dst_ip = random.choice(suspicious_ips + external_ips)
            packets.extend(generate_suspicious_traffic(src_ip, dst_ip))
            
        elif traffic_type == "normal_tcp":
            # Generate normal TCP traffic
            dst_ip = random.choice(external_ips)
            packets.extend(generate_tcp_traffic(src_ip, dst_ip))
            
        elif traffic_type == "icmp":
            # Generate ICMP traffic
            dst_ip = random.choice(external_ips)
            packets.append(generate_icmp_packet(src_ip, dst_ip))
            
        elif traffic_type == "malware":
            # Generate malware-like traffic
            dst_ip = random.choice(suspicious_ips)
            packets.extend(generate_malware_traffic(src_ip, dst_ip))
    
    # Write packets to file
    print(f"Writing {len(packets)} packets to {filename}...")
    wrpcap(filename, packets)
    print(f"Sample PCAP generated: {filename}")

def generate_http_traffic(src_ip, dst_ip, domain):
    """Generate HTTP request/response traffic"""
    packets = []
    src_port = random.randint(32768, 65535)
    dst_port = 80
    
    # HTTP GET request
    http_request = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="PA") /
        Raw(load=f"GET /index.html HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    )
    packets.append(http_request)
    
    # HTTP response
    response_data = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1234\r\n\r\n<html><body>Welcome to {domain}</body></html>"
    http_response = (
        IP(src=dst_ip, dst=src_ip) /
        TCP(sport=dst_port, dport=src_port, flags="PA") /
        Raw(load=response_data)
    )
    packets.append(http_response)
    
    return packets

def generate_dns_traffic(src_ip, dst_ip):
    """Generate DNS query/response traffic"""
    packets = []
    src_port = random.randint(32768, 65535)
    dst_port = 53
    
    # Common domains for queries
    domains = [
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "suspicious-domain.tk", "malware-c2.xyz", "phishing-site.ml"
    ]
    
    domain = random.choice(domains)
    
    # DNS query
    dns_query = (
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=src_port, dport=dst_port) /
        DNS(rd=1, qd=DNSQR(qname=domain))
    )
    packets.append(dns_query)
    
    # DNS response
    dns_response = (
        IP(src=dst_ip, dst=src_ip) /
        UDP(sport=dst_port, dport=src_port) /
        DNS(qr=1, aa=1, qd=DNSQR(qname=domain), 
            an=DNSRR(rrname=domain, rdata="93.184.216.34"))
    )
    packets.append(dns_response)
    
    return packets

def generate_suspicious_traffic(src_ip, dst_ip):
    """Generate suspicious network traffic patterns"""
    packets = []
    
    # SQL injection attempt
    sql_payload = "' UNION SELECT password FROM users WHERE id=1--"
    sql_packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=random.randint(32768, 65535), dport=80, flags="PA") /
        Raw(load=f"GET /search.php?q={sql_payload} HTTP/1.1\r\nHost: vulnerable-site.com\r\n\r\n")
    )
    packets.append(sql_packet)
    
    # XSS attempt
    xss_payload = "<script>alert('XSS')</script>"
    xss_packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=random.randint(32768, 65535), dport=80, flags="PA") /
        Raw(load=f"POST /comment.php HTTP/1.1\r\nContent-Length: {len(xss_payload)}\r\n\r\n{xss_payload}")
    )
    packets.append(xss_packet)
    
    # Command injection
    cmd_payload = "; rm -rf /; echo 'pwned'"
    cmd_packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=random.randint(32768, 65535), dport=8080, flags="PA") /
        Raw(load=f"filename={cmd_payload}")
    )
    packets.append(cmd_packet)
    
    return packets

def generate_tcp_traffic(src_ip, dst_ip):
    """Generate normal TCP traffic"""
    packets = []
    src_port = random.randint(32768, 65535)
    dst_port = random.choice([22, 443, 993, 587])  # SSH, HTTPS, IMAPS, SMTP
    
    # TCP SYN
    syn_packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="S")
    )
    packets.append(syn_packet)
    
    # TCP SYN-ACK
    synack_packet = (
        IP(src=dst_ip, dst=src_ip) /
        TCP(sport=dst_port, dport=src_port, flags="SA")
    )
    packets.append(synack_packet)
    
    # TCP ACK
    ack_packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="A")
    )
    packets.append(ack_packet)
    
    # Some data transfer
    if dst_port == 443:  # HTTPS
        data = b"\\x16\\x03\\x01\\x00\\x95\\x01\\x00\\x00\\x91\\x03\\x03"  # TLS handshake
        data_packet = (
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=src_port, dport=dst_port, flags="PA") /
            Raw(load=data)
        )
        packets.append(data_packet)
    
    return packets

def generate_icmp_packet(src_ip, dst_ip):
    """Generate ICMP ping packet"""
    icmp_packet = (
        IP(src=src_ip, dst=dst_ip) /
        ICMP(type=8, code=0) /
        Raw(load="PING test data")
    )
    return icmp_packet

def generate_malware_traffic(src_ip, dst_ip):
    """Generate malware-like traffic patterns"""
    packets = []
    
    # Base64 encoded payload (common in malware)
    base64_payload = "YWRtaW46cGFzc3dvcmQxMjM="  # admin:password123
    malware_packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=random.randint(32768, 65535), dport=8080, flags="PA") /
        Raw(load=f"data={base64_payload}")
    )
    packets.append(malware_packet)
    
    # Hexadecimal shellcode pattern
    hex_payload = "\\x48\\x31\\xc0\\x48\\x31\\xdb\\x48\\x31\\xc9"
    shellcode_packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=random.randint(32768, 65535), dport=4444, flags="PA") /
        Raw(load=hex_payload)
    )
    packets.append(shellcode_packet)
    
    # Suspicious PowerShell command
    powershell_cmd = "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    ps_packet = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=random.randint(32768, 65535), dport=80, flags="PA") /
        Raw(load=f"cmd={powershell_cmd}")
    )
    packets.append(ps_packet)
    
    return packets

def generate_realistic_timestamps(packets):
    """Add realistic timestamps to packets"""
    start_time = time.time()
    
    for i, packet in enumerate(packets):
        # Add some realistic timing variance
        timestamp = start_time + i * random.uniform(0.001, 0.1)
        packet.time = timestamp
    
    return packets

if __name__ == "__main__":
    # Create sample PCAP files of different sizes
    
    # Small sample for quick testing
    print("Creating small sample PCAP (100 packets)...")
    generate_sample_pcap("sample_small.pcap", 100)
    
    # Medium sample for normal testing
    print("Creating medium sample PCAP (1000 packets)...")
    generate_sample_pcap("sample_medium.pcap", 1000)
    
    # Large sample for performance testing
    print("Creating large sample PCAP (5000 packets)...")
    generate_sample_pcap("sample_large.pcap", 5000)
    
    print("Sample PCAP files generated successfully!")
    print("Files created:")
    print("- sample_small.pcap (100 packets)")
    print("- sample_medium.pcap (1000 packets)")
    print("- sample_large.pcap (5000 packets)")
    
    # Display file sizes
    for filename in ["sample_small.pcap", "sample_medium.pcap", "sample_large.pcap"]:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print(f"- {filename}: {size:,} bytes ({size/1024:.1f} KB)")
