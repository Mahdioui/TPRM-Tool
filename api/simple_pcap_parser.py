"""
Simple PCAP Parser for Vercel Serverless Functions
"""
import struct
import re
from collections import defaultdict

class SimplePcapParser:
    def __init__(self):
        self.threat_patterns = {
            'suspicious_domains': [
                r'\.xyz$', r'\.ru$', r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',
                r'\.gq$', r'\.co$', r'\.cc$', r'\.ws$', r'\.buzz$', r'\.cyou$'
            ],
            'malware_indicators': [
                r'cmd\.exe', r'powershell', r'wget', r'curl', r'nc\.exe',
                r'ncat', r'netcat', r'backdoor', r'rootkit', r'trojan'
            ],
            'suspicious_ports': [
                22, 23, 3389, 5900, 8080, 8443, 4444, 31337, 6667
            ]
        }
    
    def analyze_pcap(self, file_path):
        """Basic PCAP analysis without heavy dependencies"""
        try:
            with open(file_path, 'rb') as f:
                # Read PCAP header (24 bytes)
                header = f.read(24)
                if len(header) < 24:
                    return {"error": "Invalid PCAP file - header too short"}
                
                # Check magic number (0xa1b2c3d4 for big-endian)
                magic = struct.unpack('>I', header[0:4])[0]
                if magic != 0xa1b2c3d4:
                    return {"error": "Invalid PCAP file - wrong magic number"}
                
                # Parse header
                version_major = struct.unpack('>H', header[4:6])[0]
                version_minor = struct.unpack('>H', header[6:8])[0]
                
                # Read packet records
                packets = []
                protocols = defaultdict(int)
                ips = defaultdict(int)
                ports = defaultdict(int)
                threats = []
                
                packet_count = 0
                while True:
                    # Read packet header (16 bytes)
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break
                    
                    # Parse packet header
                    ts_sec = struct.unpack('>I', pkt_header[0:4])[0]
                    ts_usec = struct.unpack('>I', pkt_header[4:8])[0]
                    incl_len = struct.unpack('>I', pkt_header[8:12])[0]
                    orig_len = struct.unpack('>I', pkt_header[12:16])[0]
                    
                    if incl_len == 0:
                        continue
                    
                    # Read packet data
                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        break
                    
                    packet_count += 1
                    
                    # Basic packet analysis
                    if len(packet_data) >= 14:  # Minimum Ethernet frame size
                        # Check if it's IP packet (Ethernet type 0x0800)
                        eth_type = struct.unpack('>H', packet_data[12:14])[0]
                        if eth_type == 0x0800 and len(packet_data) >= 34:
                            # IP packet
                            ip_version = (packet_data[14] >> 4) & 0x0F
                            if ip_version == 4:  # IPv4
                                protocols['IP'] += 1
                                
                                # Extract IP addresses
                                src_ip = '.'.join(str(x) for x in packet_data[26:30])
                                dst_ip = '.'.join(str(x) for x in packet_data[30:34])
                                ips[src_ip] += 1
                                ips[dst_ip] += 1
                                
                                # Check protocol
                                if len(packet_data) >= 35:
                                    ip_proto = packet_data[23]
                                    if ip_proto == 6:  # TCP
                                        protocols['TCP'] += 1
                                        if len(packet_data) >= 38:
                                            src_port = struct.unpack('>H', packet_data[34:36])[0]
                                            dst_port = struct.unpack('>H', packet_data[36:38])[0]
                                            ports[src_port] += 1
                                            ports[dst_port] += 1
                                            
                                            # Check for suspicious ports
                                            if src_port in self.threat_patterns['suspicious_ports'] or \
                                               dst_port in self.threat_patterns['suspicious_ports']:
                                                threats.append(f"Suspicious port usage: {src_port}->{dst_port}")
                                    
                                    elif ip_proto == 17:  # UDP
                                        protocols['UDP'] += 1
                                        if len(packet_data) >= 38:
                                            src_port = struct.unpack('>H', packet_data[34:36])[0]
                                            dst_port = struct.unpack('>H', packet_data[36:38])[0]
                                            ports[src_port] += 1
                                            ports[dst_port] += 1
                                    
                                    elif ip_proto == 1:  # ICMP
                                        protocols['ICMP'] += 1
                        
                        elif eth_type == 0x0806:  # ARP
                            protocols['ARP'] += 1
                
                # Calculate risk score
                risk_score = self._calculate_risk_score(packet_count, protocols, threats, ports)
                
                # Get top talkers and ports
                top_ips = dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5])
                top_ports = dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5])
                
                return {
                    'packet_count': packet_count,
                    'protocols': dict(protocols),
                    'ips': dict(ips),
                    'ports': dict(ports),
                    'threats': threats,
                    'risk_score': risk_score,
                    'top_ips': top_ips,
                    'top_ports': top_ports,
                    'file_info': {
                        'version': f"{version_major}.{version_minor}",
                        'total_size': f"{packet_count} packets"
                    }
                }
                
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}
    
    def _calculate_risk_score(self, packet_count, protocols, threats, ports):
        """Calculate risk score from 0-100"""
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
        
        # Suspicious port usage
        suspicious_ports = [port for port in ports 
                          if port in self.threat_patterns['suspicious_ports']]
        score += len(suspicious_ports) * 10
        
        # Cap at 100
        return min(score, 100)
    
    def get_recommendations(self, analysis):
        """Get security recommendations based on analysis"""
        recommendations = []
        
        if analysis['risk_score'] > 70:
            recommendations.append("CRITICAL: Immediate security review required")
        elif analysis['risk_score'] > 50:
            recommendations.append("HIGH: Security assessment recommended")
        elif analysis['risk_score'] > 30:
            recommendations.append("MEDIUM: Monitor for suspicious activity")
        else:
            recommendations.append("LOW: Standard security practices sufficient")
        
        if analysis['threats']:
            recommendations.append("Review and investigate detected threats")
        
        if len(analysis.get('ports', {})) > 50:
            recommendations.append("Monitor for unusual port activity")
        
        return recommendations
