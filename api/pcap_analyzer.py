"""
PCAP Analysis Module for Vercel Deployment
"""
import tempfile
import os
from collections import defaultdict, Counter
import re

class PcapAnalyzer:
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
            ],
            'suspicious_protocols': [
                'FTP', 'TELNET', 'HTTP', 'SMTP'
            ]
        }
    
    def analyze_pcap(self, file_path):
        """Analyze PCAP file and return security insights"""
        try:
            # Import scapy here to avoid import issues during module loading
            from scapy.all import rdpcap, IP, TCP, UDP, DNS, HTTP
            
            # Read PCAP file
            packets = rdpcap(file_path)
            
            if not packets:
                return {"error": "No packets found in PCAP file"}
            
            # Initialize analysis results
            analysis = {
                'packet_count': len(packets),
                'protocols': defaultdict(int),
                'ips': defaultdict(int),
                'ports': defaultdict(int),
                'dns_queries': [],
                'http_requests': [],
                'threats': [],
                'risk_score': 0,
                'analysis_time': 0
            }
            
            # Analyze each packet
            for packet in packets:
                # Protocol analysis
                if IP in packet:
                    analysis['ips'][packet[IP].src] += 1
                    analysis['ips'][packet[IP].dst] += 1
                    
                    # TCP analysis
                    if TCP in packet:
                        analysis['protocols']['TCP'] += 1
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                        analysis['ports'][src_port] += 1
                        analysis['ports'][dst_port] += 1
                        
                        # Check for suspicious ports
                        if src_port in self.threat_patterns['suspicious_ports'] or \
                           dst_port in self.threat_patterns['suspicious_ports']:
                            analysis['threats'].append(f"Suspicious port usage: {src_port}->{dst_port}")
                    
                    # UDP analysis
                    elif UDP in packet:
                        analysis['protocols']['UDP'] += 1
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                        analysis['ports'][src_port] += 1
                        analysis['ports'][dst_port] += 1
                    
                    # DNS analysis
                    if DNS in packet and packet.haslayer(DNS):
                        dns_layer = packet[DNS]
                        if dns_layer.qr == 0:  # Query
                            if dns_layer.qd:
                                query = str(dns_layer.qd.qname, 'utf-8')
                                analysis['dns_queries'].append(query)
                                
                                # Check for suspicious domains
                                for pattern in self.threat_patterns['suspicious_domains']:
                                    if re.search(pattern, query, re.IGNORECASE):
                                        analysis['threats'].append(f"Suspicious DNS query: {query}")
                    
                    # HTTP analysis
                    if HTTP in packet:
                        analysis['protocols']['HTTP'] += 1
                        if packet.haslayer(HTTP):
                            http_layer = packet[HTTP]
                            if hasattr(http_layer, 'Host'):
                                host = str(http_layer.Host, 'utf-8')
                                analysis['http_requests'].append(host)
                                
                                # Check for suspicious HTTP traffic
                                if 'HTTP' in self.threat_patterns['suspicious_protocols']:
                                    analysis['threats'].append(f"HTTP traffic detected (insecure): {host}")
                
                # Other protocols
                elif packet.haslayer('ARP'):
                    analysis['protocols']['ARP'] += 1
                elif packet.haslayer('ICMP'):
                    analysis['protocols']['ICMP'] += 1
            
            # Calculate risk score
            analysis['risk_score'] = self._calculate_risk_score(analysis)
            
            # Convert defaultdict to regular dict for JSON serialization
            analysis['protocols'] = dict(analysis['protocols'])
            analysis['ips'] = dict(analysis['ips'])
            analysis['ports'] = dict(analysis['ports'])
            
            # Get top talkers and protocols
            analysis['top_ips'] = dict(Counter(analysis['ips']).most_common(5))
            analysis['top_ports'] = dict(Counter(analysis['ports']).most_common(5))
            
            return analysis
            
        except ImportError as e:
            return {"error": f"Scapy not available: {str(e)}"}
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}
    
    def _calculate_risk_score(self, analysis):
        """Calculate risk score from 0-100"""
        score = 0
        
        # Base score from packet count
        if analysis['packet_count'] > 10000:
            score += 20
        elif analysis['packet_count'] > 5000:
            score += 15
        elif analysis['packet_count'] > 1000:
            score += 10
        
        # Threat score
        score += len(analysis['threats']) * 15
        
        # Protocol risk
        if 'HTTP' in analysis['protocols']:
            score += 10
        if 'FTP' in analysis['protocols']:
            score += 20
        if 'TELNET' in analysis['protocols']:
            score += 25
        
        # Suspicious port usage
        suspicious_ports = [port for port in analysis['ports'] 
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
        
        if 'HTTP' in analysis['protocols']:
            recommendations.append("Consider implementing HTTPS for all web traffic")
        
        if analysis['threats']:
            recommendations.append("Review and investigate detected threats")
        
        if len(analysis['dns_queries']) > 100:
            recommendations.append("Monitor DNS queries for unusual patterns")
        
        return recommendations
