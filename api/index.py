from flask import Flask, jsonify, request, send_file
import tempfile
import os
import time
import struct
import json
from collections import defaultdict, Counter
import io
import re
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

class PcapAnalyzer:
    def __init__(self):
        self.threat_patterns = {
            'suspicious_ports': [22, 23, 3389, 5900, 8080, 8443, 4444, 31337, 6667],
            'suspicious_protocols': ['HTTP', 'FTP', 'TELNET'],
            'suspicious_ips': [
                '192.168.1.1', '10.0.0.1', '172.16.0.1',  # Common internal IPs
                '8.8.8.8', '1.1.1.1'  # DNS servers (usually safe)
            ]
        }
    
    def analyze_pcap(self, file_path):
        """Analyze PCAP file with real packet parsing and threat detection"""
        try:
            with open(file_path, 'rb') as f:
                # Read and validate PCAP header (24 bytes)
                header = f.read(24)
                if len(header) < 24:
                    return {"error": "Invalid PCAP file - header too short"}
                
                # Parse PCAP header
                magic = struct.unpack('>I', header[0:4])[0]
                
                # Check for valid PCAP magic numbers
                if magic in [0xa1b2c3d4, 0xa1b23c4d]:  # Big-endian formats
                    byte_order = '>'
                    precision = 'microsecond' if magic == 0xa1b2c3d4 else 'nanosecond'
                elif magic in [0xd4c3b2a1, 0x4d3cb2a1]:  # Little-endian formats
                    byte_order = '<'
                    precision = 'microsecond' if magic == 0xd4c3b2a1 else 'nanosecond'
                else:
                    return {"error": f"Invalid PCAP file - unsupported magic: 0x{magic:08x}"}
                
                # Parse header with correct byte order
                version_major = struct.unpack(f'{byte_order}H', header[4:6])[0]
                version_minor = struct.unpack(f'{byte_order}H', header[6:8])[0]
                timezone = struct.unpack(f'{byte_order}I', header[8:12])[0]
                sigfigs = struct.unpack(f'{byte_order}I', header[12:16])[0]
                snaplen = struct.unpack(f'{byte_order}I', header[16:20])[0]
                linktype = struct.unpack(f'{byte_order}I', header[20:24])[0]
                
                # Initialize enhanced analysis
                protocols = defaultdict(int)
                ips = defaultdict(int)
                ports = defaultdict(int)
                threats = []
                connections = []
                packet_sizes = []
                timestamps = []
                http_requests = []
                dns_queries = []
                suspicious_payloads = []
                encrypted_traffic = 0
                file_transfers = []
                scanning_activity = []
                anomalies = []
                
                packet_count = 0
                total_bytes = 0
                start_time = None
                
                print(f"Starting PCAP analysis of {file_path}")
                print(f"File size: {os.path.getsize(file_path)} bytes")
                print(f"PCAP header: magic=0x{magic:08x}, version={version_major}.{version_minor}, linktype={linktype}")
                
                while True:
                    # Read packet header (16 bytes)
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        print(f"End of file reached after {packet_count} packets")
                        print(f"Remaining bytes: {len(pkt_header)}")
                        break
                    
                    # Parse packet header
                    ts_sec = struct.unpack(f'{byte_order}I', pkt_header[0:4])[0]
                    ts_usec = struct.unpack(f'{byte_order}I', pkt_header[4:8])[0]
                    incl_len = struct.unpack(f'{byte_order}I', pkt_header[8:12])[0]
                    orig_len = struct.unpack(f'{byte_order}I', pkt_header[12:16])[0]
                    
                    print(f"Packet header: ts_sec={ts_sec}, incl_len={incl_len}, orig_len={orig_len}")
                    
                    if incl_len == 0:
                        print(f"Skipping packet with 0 length")
                        continue
                    
                    # Track timing
                    if start_time is None:
                        start_time = ts_sec
                    timestamps.append(ts_sec)
                    packet_sizes.append(incl_len)
                    
                    # Read packet data
                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        print(f"Failed to read packet {packet_count + 1}: expected {incl_len}, got {len(packet_data)}")
                        break
                    
                    packet_count += 1
                    total_bytes += incl_len
                    
                    print(f"Read packet {packet_count}: {len(packet_data)} bytes")
                    
                    if packet_count % 100 == 0:
                        print(f"Processed {packet_count} packets...")
                    
                    # Enhanced packet analysis with real parsing
                    if len(packet_data) >= 14:
                        eth_type = struct.unpack(f'{byte_order}H', packet_data[12:14])[0]
                        
                        print(f"  Ethernet type: 0x{eth_type:04x}")
                        
                        if eth_type == 0x0800 and len(packet_data) >= 34:  # IPv4
                            protocols['IP'] += 1
                            print(f"  IPv4 packet detected")
                            
                            # Extract IP addresses - handle different Ethernet frame formats
                            # Standard Ethernet frame: 14 bytes header + 20 bytes IP header
                            # IP addresses start at offset 26 (14 + 12) for source, 30 (14 + 16) for destination
                            if len(packet_data) >= 34:
                                src_ip = '.'.join(str(x) for x in packet_data[26:30])
                                dst_ip = '.'.join(str(x) for x in packet_data[30:34])
                                ips[src_ip] += 1
                                ips[dst_ip] += 1
                                
                                print(f"  IP addresses: {src_ip} -> {dst_ip}")
                                
                                # Debug logging for first few packets
                                if packet_count <= 5:
                                    print(f"Packet {packet_count}: {src_ip} -> {dst_ip}")
                                
                                # Check protocol (offset 23 for protocol field)
                                if len(packet_data) >= 35:
                                    ip_proto = packet_data[23]
                                    print(f"  IP protocol: {ip_proto}")
                                    
                                    if ip_proto == 6:  # TCP
                                        protocols['TCP'] += 1
                                        print(f"  TCP packet detected")
                                        if len(packet_data) >= 38:
                                            # TCP ports are at offset 34-36 and 36-38
                                            src_port = struct.unpack(f'{byte_order}H', packet_data[34:36])[0]
                                            dst_port = struct.unpack(f'{byte_order}H', packet_data[36:38])[0]
                                            ports[src_port] += 1
                                            ports[dst_port] += 1
                                            
                                            print(f"  TCP ports: {src_port} -> {dst_port}")
                                            
                                            # Debug logging for first few TCP packets
                                            if packet_count <= 5:
                                                print(f"  TCP: {src_port} -> {dst_port}")
                                            
                                            # Check for suspicious ports
                                            if src_port in self.threat_patterns['suspicious_ports'] or \
                                               dst_port in self.threat_patterns['suspicious_ports']:
                                                threats.append(f"Suspicious port usage: {src_port}->{dst_port}")
                                            
                                            # Track connections
                                            connection = {
                                                'src_ip': src_ip,
                                                'dst_ip': dst_ip,
                                                'src_port': src_port,
                                                'dst_port': dst_port,
                                                'protocol': 'TCP',
                                                'size': incl_len,
                                                'timestamp': ts_sec
                                            }
                                            connections.append(connection)
                                            
                                            # Analyze payload for threats (TCP header is 20 bytes, so payload starts at offset 54)
                                            tcp_header_len = ((packet_data[46] >> 4) & 0xF) * 4  # Get TCP header length
                                            payload_start = 34 + tcp_header_len  # IP header (20) + TCP header
                                            if len(packet_data) > payload_start:
                                                payload = packet_data[payload_start:]
                                                self._analyze_payload(payload, threats, suspicious_payloads, 
                                                                   http_requests, file_transfers, scanning_activity,
                                                                   connection, encrypted_traffic)
                                    
                                    elif ip_proto == 17:  # UDP
                                        protocols['UDP'] += 1
                                        print(f"  UDP packet detected")
                                        if len(packet_data) >= 38:
                                            # UDP ports are at offset 34-36 and 36-38
                                            src_port = struct.unpack(f'{byte_order}H', packet_data[34:36])[0]
                                            dst_port = struct.unpack(f'{byte_order}H', packet_data[36:38])[0]
                                            ports[src_port] += 1
                                            ports[dst_port] += 1
                                            
                                            print(f"  UDP ports: {src_port} -> {dst_port}")
                                            
                                            # Debug logging for first few UDP packets
                                            if packet_count <= 5:
                                                print(f"  UDP: {src_port} -> {dst_port}")
                                            
                                            # Analyze DNS queries (UDP header is 8 bytes, so payload starts at offset 42)
                                            if src_port == 53 or dst_port == 53:
                                                if len(packet_data) >= 42:
                                                    dns_payload = packet_data[42:]
                                                    self._analyze_dns_packet(dns_payload, dns_queries, connection)
                                    
                                    elif ip_proto == 1:  # ICMP
                                        protocols['ICMP'] += 1
                                        print(f"  ICMP packet detected")
                                        # Check for ping sweeps (ICMP header starts at offset 34)
                                        if len(packet_data) >= 38:
                                            icmp_type = packet_data[34]
                                            if icmp_type == 8:  # Echo request
                                                threats.append(f"ICMP ping detected from {src_ip}")
                        
                        elif eth_type == 0x0806:  # ARP
                            protocols['ARP'] += 1
                            print(f"  ARP packet detected")
                            # Check for ARP spoofing (ARP header starts at offset 14)
                            if len(packet_data) >= 22:
                                arp_op = struct.unpack(f'{byte_order}H', packet_data[20:22])[0]
                                if arp_op == 1:  # ARP request
                                    threats.append(f"ARP request from {src_ip}")
                        
                        # Debug: show packet structure for first few packets
                        if packet_count <= 3:
                            print(f"Packet {packet_count}: eth_type=0x{eth_type:04x}, length={len(packet_data)}, incl_len={incl_len}")
                            if len(packet_data) >= 14:
                                print(f"  Ethernet header: {packet_data[:14].hex()}")
                            if len(packet_data) >= 34 and eth_type == 0x0800:
                                print(f"  IP header: {packet_data[14:34].hex()}")
                    else:
                        print(f"  Packet too short for Ethernet analysis: {len(packet_data)} bytes")
                
                print(f"Analysis complete: {packet_count} packets, {total_bytes} bytes")
                print(f"Protocols found: {dict(protocols)}")
                print(f"IPs found: {len(ips)} unique IPs")
                print(f"Ports found: {len(ports)} unique ports")
                print(f"Threats detected: {len(threats)}")
                
                # Calculate additional metrics
                duration = max(timestamps) - min(timestamps) if timestamps else 0
                avg_packet_size = total_bytes / packet_count if packet_count > 0 else 0
                packets_per_second = packet_count / duration if duration > 0 else 0
                
                # Enhanced risk score calculation
                risk_score = self._calculate_enhanced_risk_score(packet_count, protocols, threats, 
                                                              ports, ips, suspicious_payloads, 
                                                              scanning_activity, encrypted_traffic)
                
                # Get top talkers and ports
                top_ips = dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10])
                top_ports = dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10])
                
                # Analyze connection patterns
                connection_analysis = self._analyze_connections(connections, ips)
                
                # Threat categorization
                threat_categories = self._categorize_threats(threats)
                
                return {
                    'packet_count': packet_count,
                    'total_bytes': total_bytes,
                    'duration_seconds': duration,
                    'avg_packet_size': round(avg_packet_size, 2),
                    'packets_per_second': round(packets_per_second, 2),
                    'protocols': dict(protocols),
                    'ips': dict(ips),
                    'ports': dict(ports),
                    'threats': threats,
                    'threat_categories': threat_categories,
                    'connections': connections[:100],  # Limit to first 100 connections
                    'risk_score': risk_score,
                    'top_ips': top_ips,
                    'top_ports': top_ports,
                    'connection_analysis': connection_analysis,
                    'http_requests': http_requests[:50],
                    'dns_queries': dns_queries[:50],
                    'suspicious_payloads': suspicious_payloads[:50],
                    'encrypted_traffic': encrypted_traffic,
                    'file_transfers': file_transfers[:50],
                    'scanning_activity': scanning_activity[:50],
                    'anomalies': anomalies,
                    'file_info': {
                        'version': f"{version_major}.{version_minor}",
                        'byte_order': 'Big-endian' if byte_order == '>' else 'Little-endian',
                        'link_type': linktype,
                        'total_size': f"{packet_count} packets ({total_bytes:,} bytes)"
                    }
                }
                
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}
    
    def _analyze_connections(self, connections, ips):
        """Analyze connection patterns and statistics"""
        if not connections:
            return {}
        
        # Connection statistics
        unique_ips = len(set([c['src_ip'] for c in connections] + [c['dst_ip'] for c in connections]))
        unique_connections = len(set([(c['src_ip'], c['dst_ip'], c['src_port'], c['dst_port']) for c in connections]))
        
        # Most active IPs
        ip_activity = defaultdict(int)
        for conn in connections:
            ip_activity[conn['src_ip']] += 1
            ip_activity[conn['dst_ip']] += 1
        
        most_active_ips = dict(sorted(ip_activity.items(), key=lambda x: x[1], reverse=True)[:5])
        
        # Connection rate analysis
        if len(connections) > 1:
            timestamps = sorted([c['timestamp'] for c in connections])
            time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_connection_rate = 1 / (sum(time_diffs) / len(time_diffs)) if time_diffs else 0
        else:
            avg_connection_rate = 0
        
        return {
            'unique_ips': unique_ips,
            'unique_connections': unique_connections,
            'most_active_ips': most_active_ips,
            'total_connections': len(connections),
            'avg_connection_rate': avg_connection_rate
        }
    
    def _analyze_payload(self, payload, threats, suspicious_payloads, http_requests, 
                         file_transfers, scanning_activity, connection, encrypted_traffic):
        """Analyze packet payload for malicious patterns using regex"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Check for malware indicators
            malware_patterns = [
                r'cmd\.exe',
                r'powershell',
                r'wget\s+http',
                r'curl\s+http',
                r'nc\s+-l',
                r'ncat\s+-l',
                r'python\s+-c',
                r'perl\s+-e',
                r'bash\s+-c',
                r'\.exe\s+download',
                r'\.bat\s+execute',
                r'\.ps1\s+invoke'
            ]
            
            for pattern in malware_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    threats.append(f"Malware indicator detected: {pattern}")
                    suspicious_payloads.append({
                        'pattern': pattern,
                        'connection': connection,
                        'payload_preview': payload_str[:200]
                    })
            
            # Check for data exfiltration
            exfiltration_patterns = [
                r'POST\s+/upload',
                r'POST\s+/data',
                r'GET\s+/download',
                r'FTP\s+STOR',
                r'SMTP\s+DATA'
            ]
            
            for pattern in exfiltration_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    threats.append(f"Data exfiltration pattern: {pattern}")
            
            # Check for scanning activity
            scanning_patterns = [
                r'port\s+scan',
                r'nmap',
                r'ping\s+sweep',
                r'arp\s+scan',
                r'syn\s+flood'
            ]
            
            for pattern in scanning_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    scanning_activity.append({
                        'pattern': pattern,
                        'connection': connection,
                        'timestamp': connection['timestamp']
                    })
            
            # Check for HTTP requests
            if 'HTTP/' in payload_str or 'GET ' in payload_str or 'POST ' in payload_str:
                self._parse_http_request(payload_str, http_requests, connection)
            
            # Check for file transfer indicators
            file_transfer_patterns = [
                r'\.exe\s+transfer',
                r'\.zip\s+download',
                r'\.rar\s+extract',
                r'\.tar\s+unpack'
            ]
            
            for pattern in file_transfer_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    file_transfers.append({
                        'pattern': pattern,
                        'connection': connection,
                        'timestamp': connection['timestamp']
                    })
            
            # Check for encrypted traffic (high entropy)
            if len(payload) > 50:
                entropy = self._calculate_entropy(payload)
                if entropy > 7.5:  # High entropy indicates encryption
                    encrypted_traffic += 1
            
        except Exception as e:
            # Continue analysis even if payload parsing fails
            pass
    
    def _parse_http_request(self, payload_str, http_requests, connection):
        """Parse HTTP request details"""
        try:
            lines = payload_str.split('\n')
            if lines and ' ' in lines[0]:
                method, path, _ = lines[0].split(' ', 2)
                
                http_request = {
                    'method': method,
                    'path': path,
                    'connection': connection,
                    'timestamp': connection['timestamp']
                }
                http_requests.append(http_request)
                
                # Check for suspicious HTTP patterns
                suspicious_paths = ['/admin', '/login', '/upload', '/shell', '/cmd', '/exec']
                for suspicious in suspicious_paths:
                    if suspicious in path.lower():
                        connection['threats'] = connection.get('threats', [])
                        connection['threats'].append(f"Suspicious HTTP path: {path}")
                        
        except Exception as e:
            # Continue analysis even if HTTP parsing fails
            pass
    
    def _analyze_dns_packet(self, dns_data, dns_queries, connection):
        """Analyze DNS packet for suspicious queries"""
        try:
            if len(dns_data) < 12:
                return
            
            # Parse DNS header
            qdcount = struct.unpack('>H', dns_data[4:6])[0]
            
            if qdcount > 0:
                # Extract query name (simplified parsing)
                query_start = 12
                query_name = ""
                pos = query_start
                
                while pos < len(dns_data) and dns_data[pos] != 0:
                    length = dns_data[pos]
                    pos += 1
                    if pos + length <= len(dns_data):
                        query_name += dns_data[pos:pos+length].decode('utf-8', errors='ignore') + "."
                        pos += length
                
                if query_name:
                    dns_queries.append({
                        'query': query_name.rstrip('.'),
                        'connection': connection,
                        'timestamp': connection['timestamp']
                    })
                    
                    # Check for suspicious domains
                    suspicious_domains = [
                        'malware', 'phishing', 'c2', 'command', 'control',
                        'backdoor', 'trojan', 'virus', 'spyware'
                    ]
                    
                    for suspicious in suspicious_domains:
                        if suspicious in query_name.lower():
                            connection['threats'] = connection.get('threats', [])
                            connection['threats'].append(f"Suspicious DNS query: {query_name}")
                            
        except Exception as e:
            # Continue analysis even if DNS parsing fails
            pass
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        try:
            if not data:
                return 0
            
            # Count byte frequencies
            byte_counts = Counter(data)
            data_len = len(data)
            
            # Calculate entropy
            entropy = 0
            for count in byte_counts.values():
                probability = count / data_len
                if probability > 0:
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
            
        except Exception:
            return 0
    
    def _categorize_threats(self, threats):
        """Categorize threats by type"""
        try:
            categories = {
                'port_scanning': [],
                'malware_indicators': [],
                'data_exfiltration': [],
                'suspicious_ips': [],
                'anomalous_traffic': []
            }
            
            for threat in threats:
                if 'port' in threat.lower():
                    categories['port_scanning'].append(threat)
                elif 'malware' in threat.lower() or 'indicator' in threat.lower():
                    categories['malware_indicators'].append(threat)
                elif 'exfiltration' in threat.lower() or 'upload' in threat.lower():
                    categories['data_exfiltration'].append(threat)
                elif 'ip' in threat.lower():
                    categories['suspicious_ips'].append(threat)
                else:
                    categories['anomalous_traffic'].append(threat)
            
            return categories
            
        except Exception as e:
            return {'error': f"Threat categorization failed: {str(e)}"}
    
    def _calculate_risk_score(self, packet_count, protocols, threats, ports, ips):
        """Calculate comprehensive risk score from 0-100"""
        score = 0
        
        # Base score from packet count
        if packet_count > 10000:
            score += 20
        elif packet_count > 5000:
            score += 15
        elif packet_count > 1000:
            score += 10
        
        # Threat score
        score += len(threats) * 15
        
        # Protocol risk
        if 'HTTP' in protocols:
            score += 10
        if 'FTP' in protocols:
            score += 20
        if 'TELNET' in protocols:
            score += 25
        
        # Suspicious port usage
        suspicious_ports = [port for port in ports 
                          if port in self.threat_patterns['suspicious_ports']]
        score += len(suspicious_ports) * 10
        
        # IP diversity risk (too many unique IPs might indicate scanning)
        if len(ips) > 100:
            score += 15
        elif len(ips) > 50:
            score += 10
        
        return min(score, 100)
    
    def _calculate_enhanced_risk_score(self, packet_count, protocols, threats, ports, ips, 
                                     suspicious_payloads, scanning_activity, encrypted_traffic):
        """Calculate enhanced risk score with additional threat factors"""
        score = 0
        
        # Base score from packet count
        if packet_count > 10000:
            score += 20
        elif packet_count > 5000:
            score += 15
        elif packet_count > 1000:
            score += 10
        
        # Threat score
        score += len(threats) * 15
        
        # Suspicious payload score
        score += len(suspicious_payloads) * 20
        
        # Scanning activity score
        score += len(scanning_activity) * 25
        
        # Encrypted traffic score (potential data exfiltration)
        if encrypted_traffic > 100:
            score += 15
        elif encrypted_traffic > 50:
            score += 10
        
        # Protocol risk
        if 'HTTP' in protocols:
            score += 10
        if 'FTP' in protocols:
            score += 20
        if 'TELNET' in protocols:
            score += 25
        
        # Suspicious port usage
        suspicious_ports = [port for port in ports 
                          if port in self.threat_patterns['suspicious_ports']]
        score += len(suspicious_ports) * 10
        
        # IP diversity risk (too many unique IPs might indicate scanning)
        if len(ips) > 100:
            score += 15
        elif len(ips) > 50:
            score += 10
        
        return min(score, 100)
    
    def get_recommendations(self, analysis):
        """Get comprehensive security recommendations based on analysis"""
        recommendations = []
        
        # Risk-based recommendations
        if analysis['risk_score'] > 70:
            recommendations.append("🚨 CRITICAL: Immediate security review required")
            recommendations.append("🔍 Conduct full network security audit")
            recommendations.append("📞 Contact security team immediately")
        elif analysis['risk_score'] > 50:
            recommendations.append("⚠️ HIGH: Security assessment recommended")
            recommendations.append("🔒 Review firewall and access controls")
            recommendations.append("📊 Monitor network traffic patterns")
        elif analysis['risk_score'] > 30:
            recommendations.append("🟡 MEDIUM: Monitor for suspicious activity")
            recommendations.append("📈 Implement enhanced logging")
            recommendations.append("🔐 Review authentication mechanisms")
        else:
            recommendations.append("🟢 LOW: Standard security practices sufficient")
            recommendations.append("✅ Continue regular security monitoring")
        
        # Specific recommendations
        if analysis['threats']:
            recommendations.append("🔍 Review and investigate detected threats")
            recommendations.append("🚫 Block suspicious IP addresses and ports")
        
        if len(analysis.get('ports', {})) > 50:
            recommendations.append("📊 Monitor for unusual port activity")
            recommendations.append("🔒 Implement port-based access controls")
        
        if analysis.get('connection_analysis', {}).get('unique_ips', 0) > 100:
            recommendations.append("🌐 Investigate high IP diversity - possible scanning activity")
        
        if 'HTTP' in analysis.get('protocols', {}):
            recommendations.append("🔒 Consider implementing HTTPS for all web traffic")
            recommendations.append("🛡️ Deploy web application firewall (WAF)")
        
        return recommendations

# Initialize analyzer
analyzer = PcapAnalyzer()

# Enhanced HTML template with comprehensive dashboard
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>PCAP Security Analyzer - Professional Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f8f9fa; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 0; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; font-size: 1.1em; }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        .upload-section { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); text-align: center; margin: 30px 0; }
        .upload-section h3 { color: #2c3e50; margin-bottom: 20px; }
        .file-input { border: 2px dashed #3498db; border-radius: 10px; padding: 40px; margin: 20px 0; transition: all 0.3s; }
        .file-input:hover { border-color: #2980b9; background: #f8f9fa; }
        .file-input input[type="file"] { margin: 20px 0; }
        .analyze-btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 40px; border: none; border-radius: 25px; cursor: pointer; font-size: 16px; font-weight: 500; transition: all 0.3s; }
        .analyze-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        
        .dashboard { display: none; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-card { background: white; padding: 25px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); text-align: center; transition: transform 0.3s; }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-number { font-size: 2.2em; font-weight: bold; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .stat-label { color: #7f8c8d; margin-top: 10px; font-size: 1em; }
        
        .section { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); margin: 25px 0; }
        .section h3 { color: #2c3e50; margin-bottom: 20px; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        
        .threat-list { background: #fff5f5; border-left: 4px solid #e74c3c; padding: 20px; border-radius: 10px; }
        .recommendations { background: #f0f9ff; border-left: 4px solid #3498db; padding: 20px; border-radius: 10px; }
        
        .download-section { text-align: center; margin: 30px 0; }
        .download-btn { background: #27ae60; color: white; padding: 15px 30px; border: none; border-radius: 25px; cursor: pointer; font-size: 16px; margin: 10px; transition: all 0.3s; }
        .download-btn:hover { background: #229954; transform: translateY(-2px); }
        
        .error { color: #e74c3c; background: #fdf2f2; padding: 15px; border-radius: 10px; margin: 15px 0; }
        .success { color: #27ae60; background: #f0f9f0; padding: 15px; border-radius: 10px; margin: 15px 0; }
        .info { color: #3498db; background: #ebf3fd; padding: 15px; border-radius: 10px; margin: 15px 0; }
        .warning { color: #f39c12; background: #fef9e7; padding: 15px; border-radius: 10px; margin: 15px 0; }
        
        .loading { text-align: center; padding: 40px; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 25px; margin: 25px 0; }
        .metric-card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 3px 10px rgba(0,0,0,0.1); }
        .metric-title { font-weight: 600; color: #2c3e50; margin-bottom: 15px; }
        .metric-value { font-size: 1.5em; color: #3498db; font-weight: bold; }
        
        .connection-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .connection-table th, .connection-table td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; }
        .connection-table th { background: #f8f9fa; font-weight: 600; color: #2c3e50; }
        .connection-table tr:hover { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 PCAP Security Analyzer</h1>
        <p>Professional Network Traffic Analysis & Threat Detection</p>
    </div>
    
    <div class="container">
        <div class="upload-section">
            <h3>Upload PCAP File for Comprehensive Security Analysis</h3>
            <div class="file-input">
                <form id="uploadForm" enctype="multipart/form-data">
                    <input type="file" name="file" accept=".pcap,.pcapng" required>
                    <br><br>
                    <button type="submit" class="analyze-btn">🚀 Analyze PCAP File</button>
                </form>
            </div>
        </div>
        
        <div id="results"></div>
        
        <div id="dashboard" class="dashboard">
            <div class="download-section">
                <button class="download-btn" onclick="downloadReport()">📊 Download Full Report (PDF)</button>
                <button class="download-btn" onclick="downloadJSON()">📄 Download Analysis Data (JSON)</button>
            </div>
        </div>
    </div>

    <script>
        let currentAnalysis = null;
        
        document.getElementById('uploadForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const resultsDiv = document.getElementById('results');
            const dashboardDiv = document.getElementById('dashboard');
            
            resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div><p>🔍 Analyzing PCAP file for security threats...</p></div>';
            dashboardDiv.style.display = 'none';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    currentAnalysis = result;
                    displayResults(result);
                    dashboardDiv.style.display = 'block';
                } else {
                    resultsDiv.innerHTML = `<div class="error">❌ Error: ${result.error}</div>`;
                }
            } catch (error) {
                resultsDiv.innerHTML = `<div class="error">❌ Error: ${error.message}</div>`;
            }
        });
        
        function displayResults(result) {
            const resultsDiv = document.getElementById('results');
            
            let html = `
                <div class="success">
                    <h3>🔍 Security Analysis Complete!</h3>
                    <p><strong>File:</strong> ${result.filename}</p>
                    <p><strong>Analysis Time:</strong> ${result.analysis_time}</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">${result.packet_count.toLocaleString()}</div>
                        <div class="stat-label">Total Packets</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${result.risk_score}</div>
                        <div class="stat-label">Risk Score /100</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${result.threats.length}</div>
                        <div class="stat-label">Threats Detected</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${Object.keys(result.protocols).length}</div>
                        <div class="stat-label">Protocols Found</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${(result.total_bytes / 1024 / 1024).toFixed(2)}</div>
                        <div class="stat-label">Total Size (MB)</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${result.connection_analysis?.unique_ips || 0}</div>
                        <div class="stat-label">Unique IPs</div>
                    </div>
                </div>
                
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-title">📊 Traffic Metrics</div>
                        <div class="metric-value">${result.duration_seconds} seconds</div>
                        <div>Duration</div>
                        <div class="metric-value">${result.packets_per_second.toFixed(2)}</div>
                        <div>Packets/Second</div>
                        <div class="metric-value">${result.avg_packet_size.toFixed(0)} bytes</div>
                        <div>Avg Packet Size</div>
                    </div>
                    
                    <div class="metric-card">
                        <div class="metric-title">🌐 Connection Analysis</div>
                        <div class="metric-value">${result.connection_analysis?.total_connections || 0}</div>
                        <div>Total Connections</div>
                        <div class="metric-value">${result.connection_analysis?.unique_connections || 0}</div>
                        <div>Unique Connections</div>
                        <div class="metric-value">${result.connection_analysis?.unique_ips || 0}</div>
                        <div>Unique IP Addresses</div>
                    </div>
                </div>
                
                <div class="section">
                    <h3>📊 Protocol Analysis</h3>
                    <p><strong>Detected Protocols:</strong> ${Object.entries(result.protocols).map(([proto, count]) => `${proto}: ${count.toLocaleString()}`).join(', ')}</p>
                </div>
                
                <div class="section">
                    <h3>🏠 Top IP Addresses</h3>
                    <div class="metrics-grid">
                        ${Object.entries(result.top_ips).map(([ip, count]) => `
                            <div class="metric-card">
                                <div class="metric-title">${ip}</div>
                                <div class="metric-value">${count.toLocaleString()}</div>
                                <div>packets</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <div class="section">
                    <h3>🔌 Top Ports</h3>
                    <div class="metrics-grid">
                        ${Object.entries(result.top_ports).map(([port, count]) => `
                            <div class="metric-card">
                                <div class="metric-title">Port ${port}</div>
                                <div class="metric-value">${count.toLocaleString()}</div>
                                <div>packets</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            
            if (result.threats && result.threats.length > 0) {
                html += `
                    <div class="section">
                        <h3>⚠️ Security Threats Detected</h3>
                        <div class="threat-list">
                            <ul>
                                ${result.threats.map(threat => `<li>${threat}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `;
            } else {
                html += '<div class="section"><h3>✅ Security Status</h3><div class="success"><h4>No immediate threats detected</h4></div></div>';
            }
            
            if (result.recommendations) {
                html += `
                    <div class="section">
                        <h3>💡 Security Recommendations</h3>
                        <div class="recommendations">
                            <ul>
                                ${result.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `;
            }
            
            resultsDiv.innerHTML = html;
        }
        
        function downloadReport() {
            if (currentAnalysis) {
                window.open('/download-report', '_blank');
            }
        }
        
        function downloadJSON() {
            if (currentAnalysis) {
                const dataStr = JSON.stringify(currentAnalysis, null, 2);
                const dataBlob = new Blob([dataStr], {type: 'application/json'});
                const url = URL.createObjectURL(dataBlob);
                const link = document.createElement('a');
                link.href = url;
                link.download = 'pcap-analysis.json';
                link.click();
                URL.revokeObjectURL(url);
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return HTML_TEMPLATE

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/test')
def test():
    """Test endpoint to verify backend functionality"""
    return jsonify({
        "status": "Backend is working!",
        "timestamp": datetime.now().isoformat(),
        "analyzer_loaded": analyzer is not None,
        "threat_patterns": len(analyzer.threat_patterns['suspicious_ports']) if analyzer else 0
    })

@app.route('/debug-pcap', methods=['POST'])
def debug_pcap():
    """Debug endpoint to see raw PCAP analysis data"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"})
        
        # Save file temporarily
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
        file.save(temp_file.name)
        temp_file.close()
        
        try:
            # Get raw analysis result
            analysis_result = analyzer.analyze_pcap(temp_file.name)
            
            # Return debug information
            debug_info = {
                "filename": file.filename,
                "file_size": os.path.getsize(temp_file.name),
                "analysis_result": analysis_result,
                "success": 'error' not in analysis_result
            }
            
            return jsonify(debug_info)
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file.name)
            except:
                pass
        
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/test-pcap-parsing')
def test_pcap_parsing():
    """Test endpoint to verify PCAP parsing logic with a simple test"""
    try:
        # Create a minimal test PCAP file in memory
        test_pcap = bytearray()
        
        # PCAP header (24 bytes)
        test_pcap.extend(struct.pack('>I', 0xa1b2c3d4))  # Magic number
        test_pcap.extend(struct.pack('>H', 2))  # Version major
        test_pcap.extend(struct.pack('>H', 4))  # Version minor
        test_pcap.extend(struct.pack('>I', 0))  # Timezone
        test_pcap.extend(struct.pack('>I', 0))  # Sigfigs
        test_pcap.extend(struct.pack('>I', 65535))  # Snaplen
        test_pcap.extend(struct.pack('>I', 1))  # Linktype (Ethernet)
        
        # Test packet header (16 bytes)
        test_pcap.extend(struct.pack('>I', 1234567890))  # Timestamp
        test_pcap.extend(struct.pack('>I', 0))  # Microseconds
        test_pcap.extend(struct.pack('>I', 60))  # Included length
        test_pcap.extend(struct.pack('>I', 60))  # Original length
        
        # Test packet data (60 bytes - minimal Ethernet + IP + TCP)
        # Ethernet header (14 bytes)
        test_pcap.extend(b'\x00\x11\x22\x33\x44\x55')  # Destination MAC
        test_pcap.extend(b'\xaa\xbb\xcc\xdd\xee\xff')  # Source MAC
        test_pcap.extend(struct.pack('>H', 0x0800))  # EtherType (IPv4)
        
        # IP header (20 bytes)
        test_pcap.extend(b'\x45')  # Version + IHL
        test_pcap.extend(b'\x00')  # Type of Service
        test_pcap.extend(struct.pack('>H', 40))  # Total Length
        test_pcap.extend(b'\x00\x00')  # Identification
        test_pcap.extend(b'\x00\x00')  # Flags + Fragment Offset
        test_pcap.extend(b'\x40')  # TTL
        test_pcap.extend(b'\x06')  # Protocol (TCP)
        test_pcap.extend(b'\x00\x00')  # Checksum
        test_pcap.extend(b'\xc0\xa8\x01\x01')  # Source IP (192.168.1.1)
        test_pcap.extend(b'\xc0\xa8\x01\x02')  # Destination IP (192.168.1.2)
        
        # TCP header (20 bytes)
        test_pcap.extend(struct.pack('>H', 12345))  # Source port
        test_pcap.extend(struct.pack('>H', 80))  # Destination port
        test_pcap.extend(b'\x00\x00\x00\x00')  # Sequence number
        test_pcap.extend(b'\x00\x00\x00\x00')  # Acknowledgement number
        test_pcap.extend(b'\x50')  # Data offset
        test_pcap.extend(b'\x00')  # Flags
        test_pcap.extend(b'\x00\x00')  # Window size
        test_pcap.extend(b'\x00\x00')  # Checksum
        test_pcap.extend(b'\x00\x00')  # Urgent pointer
        
        # Save test file temporarily
        test_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
        test_file.write(test_pcap)
        test_file.close()
        
        try:
            # Test the analyzer
            result = analyzer.analyze_pcap(test_file.name)
            
            # Also test basic file reading
            with open(test_file.name, 'rb') as f:
                # Read PCAP header
                header = f.read(24)
                magic = struct.unpack('>I', header[0:4])[0]
                version_major = struct.unpack('>H', header[4:6])[0]
                version_minor = struct.unpack('>H', header[6:8])[0]
                
                # Try to read first packet header
                pkt_header = f.read(16)
                pkt_header_len = len(pkt_header)
                
                # Try to read packet data
                if pkt_header_len == 16:
                    incl_len = struct.unpack('>I', pkt_header[8:12])[0]
                    packet_data = f.read(incl_len)
                    packet_data_len = len(packet_data)
                else:
                    incl_len = 0
                    packet_data_len = 0
            
            test_info = {
                "test_pcap_created": True,
                "test_file_size": len(test_pcap),
                "test_analysis_result": result,
                "test_success": 'error' not in result,
                "debug_info": {
                    "pcap_header": {
                        "magic": f"0x{magic:08x}",
                        "version": f"{version_major}.{version_minor}",
                        "header_size": len(header)
                    },
                    "packet_header": {
                        "read_length": pkt_header_len,
                        "expected_length": 16,
                        "incl_len": incl_len
                    },
                    "packet_data": {
                        "read_length": packet_data_len,
                        "expected_length": incl_len
                    }
                }
            }
            
            return jsonify(test_info)
            
        finally:
            # Clean up test file
            try:
                os.unlink(test_file.name)
            except:
                pass
        
    except Exception as e:
        return jsonify({"error": f"Test failed: {str(e)}"})

@app.route('/analyze', methods=['POST'])
def analyze_pcap():
    try:
        if 'file' not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"success": False, "error": "No file selected"})
        
        if not file.filename.lower().endswith(('.pcap', '.pcapng')):
            return jsonify({"success": False, "error": "Invalid file type. Please upload a .pcap or .pcapng file"})
        
        # Save file temporarily
        start_time = time.time()
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
        file.save(temp_file.name)
        temp_file.close()
        
        try:
            # Analyze the PCAP file
            analysis_result = analyzer.analyze_pcap(temp_file.name)
            
            if 'error' in analysis_result:
                return jsonify({"success": False, "error": analysis_result['error']})
            
            # Add additional information
            analysis_result['success'] = True
            analysis_result['filename'] = file.filename
            analysis_result['analysis_time'] = f"{time.time() - start_time:.2f} seconds"
            
            # Get recommendations
            analysis_result['recommendations'] = analyzer.get_recommendations(analysis_result)
            
            return jsonify(analysis_result)
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file.name)
            except:
                pass
        
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/download-report')
def download_report():
    """Generate and download a comprehensive PDF report"""
    try:
        # For now, return a simple text report
        # In a full implementation, this would generate a professional PDF
        report_content = """
PCAP Security Analysis Report
=============================

This is a comprehensive security analysis report.
In the full version, this would include:
- Executive summary
- Technical analysis
- Threat assessment
- Risk scoring
- Recommendations
- Charts and graphs
- Appendices

Generated by PCAP Security Analyzer
        """
        
        # Create a text file for now
        report_io = io.BytesIO()
        report_io.write(report_content.encode('utf-8'))
        report_io.seek(0)
        
        return send_file(
            report_io,
            as_attachment=True,
            download_name='pcap-security-report.txt',
            mimetype='text/plain'
        )
        
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"})

if __name__ == "__main__":
    app.run()
