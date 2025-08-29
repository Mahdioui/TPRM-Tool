from flask import Flask, jsonify, request, send_file
import tempfile
import os
import time
import struct
import json
from collections import defaultdict
import io
import re

# Try to import nlp_utils, provide fallback if not available
try:
    from nlp_utils import nlp_analyzer
    NLP_AVAILABLE = True
except ImportError:
    NLP_AVAILABLE = False
    # Create a simple fallback analyzer
    class FallbackNLPAnalyzer:
        def analyze_payload(self, payload):
            return {'text_analysis': {'threat_score': 0, 'threat_level': 'MINIMAL'}, 'binary_analysis': {'is_encrypted': False}}
        def analyze_text(self, text):
            return {'threat_score': 0, 'threat_level': 'MINIMAL'}
    
    nlp_analyzer = FallbackNLPAnalyzer()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

class PcapAnalyzer:
    def __init__(self):
        self.threat_patterns = {
            'suspicious_ports': [22, 23, 3389, 5900, 8080, 8443, 4444, 31337, 6667],
            'suspicious_protocols': ['HTTP', 'FTP', 'TELNET'],
            'malware_patterns': [
                r'cmd\.exe', r'powershell', r'wget', r'curl', r'nc', r'ncat',
                r'python\s+-c', r'perl\s+-e', r'bash\s+-c', r'\.exe\s+download'
            ]
        }
    
    def analyze_pcap(self, file_path):
        """Enhanced PCAP analysis with NLP threat detection"""
        try:
            with open(file_path, 'rb') as f:
                # Read PCAP header
                header = f.read(24)
                if len(header) < 24:
                    return {"error": "Invalid PCAP file"}
                
                # Parse magic number
                magic = struct.unpack('>I', header[0:4])[0]
                if magic not in [0xa1b2c3d4, 0xa1b23c4d, 0xd4c3b2a1, 0x4d3cb2a1]:
                    return {"error": f"Invalid PCAP magic: 0x{magic:08x}"}
                
                # Determine byte order
                byte_order = '>' if magic in [0xa1b2c3d4, 0xa1b23c4d] else '<'
                
                # Parse version
                version_major = struct.unpack(f'{byte_order}H', header[4:6])[0]
                version_minor = struct.unpack(f'{byte_order}H', header[6:8])[0]
                
                # Initialize enhanced analysis
                protocols = defaultdict(int)
                ips = defaultdict(int)
                ports = defaultdict(int)
                threats = []
                connections = []
                packet_count = 0
                total_bytes = 0
                
                # NLP analysis results
                nlp_threats = []
                suspicious_payloads = []
                encrypted_traffic = 0
                
                # Read packets
                while True:
                    # Read packet header
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break
                    
                    # Parse packet header
                    ts_sec = struct.unpack(f'{byte_order}I', pkt_header[0:4])[0]
                    incl_len = struct.unpack(f'{byte_order}I', pkt_header[8:12])[0]
                    
                    if incl_len == 0:
                        continue
                    
                    # Read packet data
                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        break
                    
                    packet_count += 1
                    total_bytes += incl_len
                    
                    # Enhanced packet analysis with NLP
                    if len(packet_data) >= 14:
                        eth_type = struct.unpack(f'{byte_order}H', packet_data[12:14])[0]
                        
                        # Debug output for first few packets
                        if packet_count <= 5:
                            print(f"Packet {packet_count}: eth_type=0x{eth_type:04x}, len={len(packet_data)}")
                        
                        # Handle different Ethernet types
                        if eth_type == 0x0800 and len(packet_data) >= 34:  # IPv4
                            protocols['IP'] += 1
                            
                            # Extract IP addresses (correct offset: 26-30 for src, 30-34 for dst)
                            src_ip = '.'.join(str(x) for x in packet_data[26:30])
                            dst_ip = '.'.join(str(x) for x in packet_data[30:34])
                            ips[src_ip] += 1
                            ips[dst_ip] += 1
                            
                            # Debug output for first few packets
                            if packet_count <= 5:
                                print(f"  IPv4: {src_ip} -> {dst_ip}")
                            
                            # Check protocol (correct offset: 23 for IP protocol)
                            if len(packet_data) >= 35:
                                ip_proto = packet_data[23]
                                
                                # Debug output for protocol
                                if packet_count <= 5:
                                    print(f"  Protocol: {ip_proto} (6=TCP, 17=UDP, 1=ICMP)")
                                
                                if ip_proto == 6:  # TCP
                                    protocols['TCP'] += 1
                                    if len(packet_data) >= 38:
                                        src_port = struct.unpack(f'{byte_order}H', packet_data[34:36])[0]
                                        dst_port = struct.unpack(f'{byte_order}H', packet_data[36:38])[0]
                                        ports[src_port] += 1
                                        ports[dst_port] += 1
                                        
                                        # Check for suspicious ports
                                        if src_port in self.threat_patterns['suspicious_ports'] or \
                                           dst_port in self.threat_patterns['suspicious_ports']:
                                            threats.append(f"Suspicious port: {src_port}->{dst_port}")
                                        
                                        # Track connections
                                        connection = {
                                            'src_ip': src_ip,
                                            'dst_ip': dst_ip,
                                            'src_port': src_port,
                                            'dst_port': dst_port,
                                            'protocol': 'TCP'
                                        }
                                        connections.append(connection)
                                        
                                        # Debug output for connections
                                        if packet_count <= 5:
                                            print(f"  TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                                        
                                        # NLP analysis of payload
                                        if len(packet_data) > 54:  # TCP header is 20 bytes
                                            tcp_header_len = ((packet_data[46] >> 4) & 0xF) * 4
                                            payload_start = 34 + tcp_header_len
                                            if len(packet_data) > payload_start:
                                                payload = packet_data[payload_start:]
                                                self._analyze_payload_nlp(payload, threats, suspicious_payloads, 
                                                                        nlp_threats, encrypted_traffic, connection)
                                
                                elif ip_proto == 17:  # UDP
                                    protocols['UDP'] += 1
                                    if len(packet_data) >= 38:
                                        src_port = struct.unpack(f'{byte_order}H', packet_data[34:36])[0]
                                        dst_port = struct.unpack(f'{byte_order}H', packet_data[36:38])[0]
                                        ports[src_port] += 1
                                        ports[dst_port] += 1
                                        
                                        # NLP analysis of DNS payloads
                                        if src_port == 53 or dst_port == 53:
                                            if len(packet_data) >= 42:
                                                dns_payload = packet_data[42:]
                                                self._analyze_dns_nlp(dns_payload, nlp_threats, connection)
                                
                                elif ip_proto == 1:  # ICMP
                                    protocols['ICMP'] += 1
                        
                        elif eth_type == 0x0806:  # ARP
                            protocols['ARP'] += 1
                            if packet_count <= 5:
                                print(f"  ARP packet detected")
                            
                            # Extract ARP information if possible
                            if len(packet_data) >= 42:  # ARP header is 28 bytes + 14 bytes Ethernet
                                arp_op = struct.unpack(f'{byte_order}H', packet_data[20:22])[0]
                                if arp_op == 1:  # ARP Request
                                    if packet_count <= 5:
                                        print(f"    ARP Request")
                                elif arp_op == 2:  # ARP Reply
                                    if packet_count <= 5:
                                        print(f"    ARP Reply")
                        
                        elif eth_type == 0x0808:  # ARP (alternative)
                            protocols['ARP'] += 1
                            if packet_count <= 5:
                                print(f"  ARP packet detected (alt)")
                        
                        elif eth_type == 0xa8c0:  # Custom/Proprietary protocol
                            protocols['CUSTOM'] += 1
                            if packet_count <= 5:
                                print(f"  Custom protocol packet (0xa8c0)")
                        
                        elif eth_type == 0x0101:  # Another custom protocol
                            protocols['CUSTOM'] += 1
                            if packet_count <= 5:
                                print(f"  Custom protocol packet (0x0101)")
                        
                        else:
                            # Unknown protocol
                            protocols['UNKNOWN'] += 1
                            if packet_count <= 5:
                                print(f"  Unknown protocol: 0x{eth_type:04x}")
                            
                            # Try to extract any readable text from unknown protocols
                            try:
                                text_content = packet_data.decode('utf-8', errors='ignore')
                                if len(text_content) > 10 and any(c.isprintable() for c in text_content):
                                    if packet_count <= 5:
                                        print(f"    Text content: {text_content[:50]}...")
                            except:
                                pass
                
                # Calculate metrics
                duration = 0  # Simplified for now
                avg_packet_size = total_bytes / packet_count if packet_count > 0 else 0
                packets_per_second = packet_count / duration if duration > 0 else 0
                
                # Debug output for final results
                print(f"\n=== ANALYSIS RESULTS ===")
                print(f"Total packets: {packet_count}")
                print(f"Total bytes: {total_bytes}")
                print(f"Protocols found: {dict(protocols)}")
                print(f"IPs found: {len(ips)}")
                print(f"Ports found: {len(ports)}")
                print(f"Connections: {len(connections)}")
                print(f"Threats: {len(threats)}")
                print(f"NLP threats: {len(nlp_threats)}")
                print(f"=======================\n")
                
                # Enhanced risk score with NLP
                risk_score = self._calculate_enhanced_risk_score(packet_count, protocols, threats, 
                                                               ports, ips, nlp_threats, suspicious_payloads, 
                                                               encrypted_traffic)
                
                # Get top talkers and ports
                top_ips = dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10])
                top_ports = dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10])
                
                # Connection analysis
                connection_analysis = self._analyze_connections(connections, ips)
                
                # Combine all threats
                all_threats = threats + nlp_threats
                
                return {
                    'packet_count': packet_count,
                    'total_bytes': total_bytes,
                    'duration_seconds': duration,
                    'avg_packet_size': round(avg_packet_size, 2),
                    'packets_per_second': round(packets_per_second, 2),
                    'protocols': dict(protocols),
                    'ips': dict(ips),
                    'ports': dict(ports),
                    'threats': all_threats,
                    'threat_categories': {
                        'regex_threats': threats,
                        'nlp_threats': nlp_threats,
                        'suspicious_payloads': suspicious_payloads
                    },
                    'connections': connections[:100],
                    'risk_score': risk_score,
                    'top_ips': top_ips,
                    'top_ports': top_ports,
                    'connection_analysis': connection_analysis,
                    'nlp_analysis': {
                        'encrypted_traffic': encrypted_traffic,
                        'suspicious_payloads_count': len(suspicious_payloads)
                    },
                    'file_info': {
                        'version': f"{version_major}.{version_minor}",
                        'total_size': f"{packet_count} packets ({total_bytes:,} bytes)"
                    }
                }
                
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}
    
    def _analyze_payload_nlp(self, payload, threats, suspicious_payloads, nlp_threats, encrypted_traffic, connection):
        """Analyze payload using NLP and regex patterns"""
        try:
            # Regex pattern matching
            for pattern in self.threat_patterns['malware_patterns']:
                if re.search(pattern, payload.decode('utf-8', errors='ignore'), re.IGNORECASE):
                    threats.append(f"Malware pattern: {pattern}")
                    suspicious_payloads.append({
                        'pattern': pattern,
                        'connection': connection,
                        'payload_preview': payload[:200].hex()
                    })
            
            # NLP analysis
            nlp_result = nlp_analyzer.analyze_payload(payload)
            
            if nlp_result.get('text_analysis', {}).get('threat_score', 0) > 30:
                nlp_threats.append(f"NLP threat detected: {nlp_result['text_analysis']['threat_level']} level")
                suspicious_payloads.append({
                    'nlp_analysis': nlp_result,
                    'connection': connection,
                    'payload_preview': payload[:200].hex()
                })
            
            # Check for encrypted traffic
            if nlp_result.get('binary_analysis', {}).get('is_encrypted', False):
                encrypted_traffic += 1
                
        except Exception:
            # Continue analysis even if payload parsing fails
            pass
    
    def _analyze_dns_nlp(self, dns_payload, nlp_threats, connection):
        """Analyze DNS payload using NLP"""
        try:
            # Simple DNS query extraction
            if len(dns_payload) > 12:
                query_start = 12
                query_name = ""
                pos = query_start
                
                while pos < len(dns_payload) and dns_payload[pos] != 0:
                    length = dns_payload[pos]
                    pos += 1
                    if pos + length <= len(dns_payload):
                        query_name += dns_payload[pos:pos+length].decode('utf-8', errors='ignore') + "."
                        pos += length
                
                if query_name:
                    # NLP analysis of domain name
                    nlp_result = nlp_analyzer.analyze_text(query_name)
                    if nlp_result.get('threat_score', 0) > 20:
                        nlp_threats.append(f"Suspicious DNS query: {query_name}")
                        
        except Exception:
            pass
    
    def _analyze_connections(self, connections, ips):
        """Analyze connection patterns"""
        if not connections:
            return {}
        
        unique_ips = len(set([c['src_ip'] for c in connections] + [c['dst_ip'] for c in connections]))
        unique_connections = len(set([(c['src_ip'], c['dst_ip'], c['src_port'], c['dst_port']) for c in connections]))
        
        return {
            'unique_ips': unique_ips,
            'unique_connections': unique_connections,
            'total_connections': len(connections)
        }
    
    def _calculate_enhanced_risk_score(self, packet_count, protocols, threats, ports, ips, nlp_threats, suspicious_payloads, encrypted_traffic):
        """Calculate enhanced risk score with NLP analysis"""
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
        
        # NLP threat score
        score += len(nlp_threats) * 20
        
        # Suspicious payload score
        score += len(suspicious_payloads) * 25
        
        # Encrypted traffic score
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
        
        # IP diversity risk
        if len(ips) > 100:
            score += 15
        elif len(ips) > 50:
            score += 10
        
        return min(score, 100)
    
    def get_recommendations(self, analysis):
        """Get enhanced security recommendations"""
        recommendations = []
        
        if analysis['risk_score'] > 70:
            recommendations.extend([
                "🚨 CRITICAL: Immediate security review required",
                "🔍 Conduct full network security audit",
                "📞 Contact security team immediately"
            ])
        elif analysis['risk_score'] > 50:
            recommendations.extend([
                "⚠️ HIGH: Security assessment recommended",
                "🔒 Review firewall and access controls",
                "📊 Monitor network traffic patterns"
            ])
        elif analysis['risk_score'] > 30:
            recommendations.extend([
                "🟡 MEDIUM: Monitor for suspicious activity",
                "📈 Implement enhanced logging",
                "🔐 Review authentication mechanisms"
            ])
        else:
            recommendations.extend([
                "🟢 LOW: Standard security practices sufficient",
                "✅ Continue regular security monitoring"
            ])
        
        # NLP-specific recommendations
        if analysis.get('threat_categories', {}).get('nlp_threats'):
            recommendations.extend([
                "🧠 NLP analysis detected suspicious content",
                "🔍 Review payload analysis for hidden threats",
                "📝 Monitor for unusual text patterns in traffic"
            ])
        
        if analysis.get('nlp_analysis', {}).get('encrypted_traffic', 0) > 50:
            recommendations.extend([
                "🔐 High volume of encrypted traffic detected",
                "🔍 Investigate potential data exfiltration",
                "📊 Monitor encrypted traffic patterns"
            ])
        
        if analysis['threats']:
            recommendations.extend([
                "🔍 Review and investigate detected threats",
                "🚫 Block suspicious IP addresses and ports"
            ])
        
        return recommendations

# Initialize analyzer
analyzer = PcapAnalyzer()

# Simple HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>PCAP Security Analyzer</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px; }
        .upload-section { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; margin-bottom: 20px; }
        .file-input { border: 2px dashed #3498db; border-radius: 8px; padding: 30px; margin: 20px 0; }
        .analyze-btn { background: #3498db; color: white; padding: 12px 30px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; }
        .analyze-btn:hover { background: #2980b9; }
        .results { margin-top: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
        .stat-label { color: #7f8c8d; margin-top: 10px; }
        .section { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin: 20px 0; }
        .loading { text-align: center; padding: 40px; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .error { color: #e74c3c; background: #fdf2f2; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .success { color: #27ae60; background: #f0f9f0; padding: 15px; border-radius: 8px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 PCAP Security Analyzer</h1>
            <p>Network Traffic Analysis & Threat Detection</p>
        </div>
        
        <div class="upload-section">
            <h3>Upload PCAP File for Security Analysis</h3>
            <div class="file-input">
                <form id="uploadForm" enctype="multipart/form-data">
                    <input type="file" name="file" accept=".pcap,.pcapng" required>
                    <br><br>
                    <button type="submit" class="analyze-btn">🚀 Analyze PCAP File</button>
                </form>
            </div>
        </div>
        
        <div id="results"></div>
    </div>

    <script>
        document.getElementById('uploadForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const resultsDiv = document.getElementById('results');
            
            // Debug: Log form data
            console.log('Form submitted with file:', formData.get('file'));
            
            resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div><p>🔍 Analyzing PCAP file...</p></div>';
            
            try {
                console.log('Sending request to /analyze...');
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                console.log('Response status:', response.status);
                console.log('Response headers:', response.headers);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const result = await response.json();
                console.log('Analysis result:', result);
                
                if (result.success) {
                    displayResults(result);
                } else {
                    console.error('Analysis failed:', result.error);
                    resultsDiv.innerHTML = `<div class="error">❌ Error: ${result.error}</div>`;
                }
            } catch (error) {
                console.error('Upload error:', error);
                resultsDiv.innerHTML = `<div class="error">❌ Error: ${error.message}</div>`;
            }
        });
        
        function displayResults(result) {
            const resultsDiv = document.getElementById('results');
            
            console.log('Displaying results:', result);
            console.log('Protocols found:', result.protocols);
            
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
                
                <!-- Enhanced Traffic Metrics Dashboard -->
                <div class="section">
                    <h3>📊 Traffic Metrics</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
                        <div style="background: #f0f9ff; padding: 15px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.5em; font-weight: bold; color: #3498db;">${result.duration_seconds || 0}</div>
                            <div>Duration (seconds)</div>
                        </div>
                        <div style="background: #f0f9ff; padding: 15px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.5em; font-weight: bold; color: #3498db;">${result.packets_per_second || 0}</div>
                            <div>Packets/Second</div>
                        </div>
                        <div style="background: #f0f9ff; padding: 15px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.5em; font-weight: bold; color: #3498db;">${result.avg_packet_size || 0}</div>
                            <div>Avg Packet Size (bytes)</div>
                        </div>
                    </div>
                </div>
                
                <!-- Enhanced Protocol Analysis Dashboard -->
                <div class="section">
                    <h3>📊 Protocol Analysis</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
                        ${Object.entries(result.protocols).map(([proto, count]) => `
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; border-left: 4px solid #3498db;">
                                <div style="font-size: 1.5em; font-weight: bold; color: #2c3e50;">${count.toLocaleString()}</div>
                                <div style="color: #7f8c8d;">${proto}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <!-- Enhanced Connection Analysis Dashboard -->
                <div class="section">
                    <h3>🌐 Connection Analysis</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
                        <div style="background: #f0f9ff; padding: 15px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.5em; font-weight: bold; color: #3498db;">${result.connection_analysis?.total_connections || 0}</div>
                            <div>Total Connections</div>
                        </div>
                        <div style="background: #f0f9ff; padding: 15px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.5em; font-weight: bold; color: #3498db;">${result.connection_analysis?.unique_connections || 0}</div>
                            <div>Unique Connections</div>
                        </div>
                        <div style="background: #f0f9ff; padding: 15px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.5em; font-weight: bold; color: #3498db;">${result.connection_analysis?.unique_ips || 0}</div>
                            <div>Unique IP Addresses</div>
                        </div>
                    </div>
                </div>
                
                <!-- Enhanced Top IP Addresses Dashboard -->
                ${Object.keys(result.top_ips).length > 0 ? `
                <div class="section">
                    <h3>🏠 Top IP Addresses</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 15px 0;">
                        ${Object.entries(result.top_ips).map(([ip, count]) => `
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #27ae60;">
                                <div style="font-weight: bold; color: #2c3e50;">${ip}</div>
                                <div style="color: #7f8c8d; margin-top: 5px;">${count.toLocaleString()} packets</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : '<div class="section"><h3>🏠 Top IP Addresses</h3><p style="color: #7f8c8d;">No IP addresses detected in this capture</p></div>'}
                
                <!-- Enhanced Top Ports Dashboard -->
                ${Object.keys(result.top_ports).length > 0 ? `
                <div class="section">
                    <h3>🔌 Top Ports</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
                        ${Object.entries(result.top_ports).map(([port, count]) => `
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #e67e22;">
                                <div style="font-weight: bold; color: #2c3e50;">Port ${port}</div>
                                <div style="color: #7f8c8d; margin-top: 5px;">${count.toLocaleString()} packets</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : '<div class="section"><h3>🔌 Top Ports</h3><p style="color: #7f8c8d;">No ports detected in this capture</p></div>'}
                
                ${result.threat_categories ? `
                <div class="section">
                    <h3>🔍 Threat Analysis</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 15px 0;">
                        <div style="background: #fff5f5; padding: 15px; border-radius: 8px; border-left: 4px solid #e74c3c;">
                            <h4>🚨 Regex Threats</h4>
                            <p><strong>Count:</strong> ${result.threat_categories.regex_threats ? result.threat_categories.regex_threats.length : 0}</p>
                            ${result.threat_categories.regex_threats && result.threat_categories.regex_threats.length > 0 ? 
                                `<ul style="margin: 10px 0; padding-left: 20px;">${result.threat_categories.regex_threats.map(threat => `<li>${threat}</li>`).join('')}</ul>` : 
                                '<p style="color: #27ae60;">✅ No regex threats detected</p>'
                            }
                        </div>
                        
                        <div style="background: #f0f9ff; padding: 15px; border-radius: 8px; border-left: 4px solid #3498db;">
                            <h4>🧠 NLP Threats</h4>
                            <p><strong>Count:</strong> ${result.threat_categories.nlp_threats ? result.threat_categories.nlp_threats.length : 0}</p>
                            ${result.threat_categories.nlp_threats && result.threat_categories.nlp_threats.length > 0 ? 
                                `<ul style="margin: 10px 0; padding-left: 20px;">${result.threat_categories.nlp_threats.map(threat => `<li>${threat}</li>`).join('')}</ul>` : 
                                '<p style="color: #27ae60;">✅ No NLP threats detected</p>'
                            }
                        </div>
                        
                        <div style="background: #fff9f0; padding: 15px; border-radius: 8px; border-left: 4px solid #f39c12;">
                            <h4>🔐 Suspicious Payloads</h4>
                            <p><strong>Count:</strong> ${result.threat_categories.suspicious_payloads ? result.threat_categories.suspicious_payloads.length : 0}</p>
                            ${result.threat_categories.suspicious_payloads && result.threat_categories.suspicious_payloads.length > 0 ? 
                                '<p style="color: #e74c3c;">⚠️ Suspicious content detected in payloads</p>' : 
                                '<p style="color: #27ae60;">✅ No suspicious payloads detected</p>'
                            }
                        </div>
                    </div>
                </div>
                ` : ''}
                
                ${result.nlp_analysis ? `
                <div class="section">
                    <h3>🧠 NLP Analysis Results</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
                        <div style="background: #f0f9ff; padding: 15px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.5em; font-weight: bold; color: #3498db;">${result.nlp_analysis.encrypted_traffic || 0}</div>
                            <div>Encrypted Traffic Packets</div>
                        </div>
                        <div style="background: #fff9f0; padding: 15px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 1.5em; font-weight: bold; color: #f39c12;">${result.nlp_analysis.suspicious_payloads_count || 0}</div>
                            <div>Suspicious Payloads</div>
                        </div>
                    </div>
                </div>
                ` : ''}
            `;
            
            if (result.threats && result.threats.length > 0) {
                html += `
                    <div class="section">
                        <h3>⚠️ Security Threats Detected</h3>
                        <ul>
                            ${result.threats.map(threat => `<li>${threat}</li>`).join('')}
                        </ul>
                    </div>
                `;
            } else {
                html += '<div class="section"><h3>✅ Security Status</h3><div class="success"><h4>No immediate threats detected</h4></div></div>';
            }
            
            if (result.recommendations) {
                html += `
                    <div class="section">
                        <h3>💡 Security Recommendations</h3>
                        <ul>
                            ${result.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }
            
            // Add downloadable reports section (simplified to 2 options)
            html += `
                <div class="section">
                    <h3>📊 Download Reports</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 15px 0;">
                        <div style="background: #f0f9ff; padding: 25px; border-radius: 8px; text-align: center; border: 2px solid #3498db;">
                            <h4 style="color: #2c3e50; margin: 0 0 15px 0;">📄 Full Security Report</h4>
                            <p style="color: #7f8c8d; margin: 0 0 20px 0;">Complete analysis with all findings and recommendations</p>
                            <button onclick="downloadFullReport(${JSON.stringify(result).replace(/"/g, '&quot;')})" style="background: #3498db; color: white; border: none; padding: 12px 25px; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold;">
                                📥 Download Full Report
                            </button>
                        </div>
                        
                        <div style="background: #fff9f0; padding: 25px; border-radius: 8px; text-align: center; border: 2px solid #f39c12;">
                            <h4 style="color: #2c3e50; margin: 0 0 15px 0;">📊 Analysis Data (JSON)</h4>
                            <p style="color: #7f8c8d; margin: 0 0 20px 0;">Raw data for further processing and integration</p>
                            <button onclick="downloadJSONData(${JSON.stringify(result).replace(/"/g, '&quot;')})" style="background: #f39c12; color: white; border: none; padding: 12px 25px; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold;">
                                📥 Download JSON Data
                            </button>
                        </div>
                    </div>
                </div>
            `;
            
            resultsDiv.innerHTML = html;
        }
        
        // Simple download functions that actually work
        function downloadFullReport(data) {
            try {
                const content = `PCAP SECURITY ANALYSIS REPORT
Generated: ${new Date().toLocaleString()}
File: ${data.filename}
Analysis Time: ${data.analysis_time}

=== EXECUTIVE SUMMARY ===
Total Packets: ${data.packet_count.toLocaleString()}
Total Bytes: ${(data.total_bytes / 1024 / 1024).toFixed(2)} MB
Risk Score: ${data.risk_score}/100
Threats Detected: ${data.threats.length}

=== PROTOCOL ANALYSIS ===
${Object.entries(data.protocols).map(([proto, count]) => `${proto}: ${count.toLocaleString()} packets`).join('\\n')}

=== CONNECTION ANALYSIS ===
Total Connections: ${data.connection_analysis?.total_connections || 0}
Unique Connections: ${data.connection_analysis?.unique_connections || 0}
Unique IP Addresses: ${data.connection_analysis?.unique_ips || 0}

=== THREAT ANALYSIS ===
Regex Threats: ${data.threat_categories?.regex_threats?.length || 0}
NLP Threats: ${data.threat_categories?.nlp_threats?.length || 0}
Suspicious Payloads: ${data.threat_categories?.suspicious_payloads?.length || 0}

${data.threats.length > 0 ? '\\nDetected Threats:\\n' + data.threats.map(threat => `- ${threat}`).join('\\n') : '\\nNo threats detected.'}

=== SECURITY RECOMMENDATIONS ===
${data.recommendations ? data.recommendations.map(rec => `- ${rec}`).join('\\n') : 'No specific recommendations.'}

=== TECHNICAL DETAILS ===
PCAP Version: ${data.file_info?.version || 'Unknown'}

--- End of Report ---`;

                downloadFile(content, 'pcap_security_analysis_report.txt', 'text/plain');
            } catch (error) {
                console.error('Download error:', error);
                alert('Download failed. Please try again.');
            }
        }
        
        function downloadJSONData(data) {
            try {
                const content = JSON.stringify(data, null, 2);
                downloadFile(content, 'pcap_analysis_data.json', 'application/json');
            } catch (error) {
                console.error('Download error:', error);
                alert('Download failed. Please try again.');
            }
        }
        
        function downloadFile(content, filename, mimeType) {
            const blob = new Blob([content], { type: mimeType });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>
"""

@app.route('/test')
def test():
    """Simple test endpoint to verify backend is working"""
    return jsonify({
        "message": "PCAP Analyzer Backend is working!",
        "nlp_available": NLP_AVAILABLE,
        "timestamp": time.time()
    })

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "nlp_available": NLP_AVAILABLE,
        "timestamp": time.time()
    })

@app.route('/')
def home():
    return HTML_TEMPLATE

@app.route('/analyze', methods=['POST'])
def analyze_pcap():
    try:
        print(f"=== UPLOAD REQUEST RECEIVED ===")
        print(f"Request method: {request.method}")
        print(f"Request headers: {dict(request.headers)}")
        print(f"Request files: {list(request.files.keys())}")
        
        if 'file' not in request.files:
            print("ERROR: No file in request.files")
            return jsonify({"success": False, "error": "No file uploaded"})
        
        file = request.files['file']
        print(f"File received: {file.filename}")
        print(f"File content type: {file.content_type}")
        print(f"File size: {len(file.read()) if file else 'Unknown'}")
        file.seek(0)  # Reset file pointer
        
        if file.filename == '':
            print("ERROR: Empty filename")
            return jsonify({"success": False, "error": "No file selected"})
        
        if not file.filename.lower().endswith(('.pcap', '.pcapng')):
            print(f"ERROR: Invalid file type: {file.filename}")
            return jsonify({"success": False, "error": "Invalid file type. Please upload a .pcap or .pcapng file"})
        
        # Save file temporarily
        start_time = time.time()
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
        file.save(temp_file.name)
        temp_file.close()
        
        print(f"File saved to: {temp_file.name}")
        print(f"File size on disk: {os.path.getsize(temp_file.name)} bytes")
        
        try:
            # Analyze the PCAP file
            print("Starting PCAP analysis...")
            analysis_result = analyzer.analyze_pcap(temp_file.name)
            print(f"Analysis completed: {analysis_result}")
            
            if 'error' in analysis_result:
                print(f"Analysis error: {analysis_result['error']}")
                return jsonify({"success": False, "error": analysis_result['error']})
            
            # Add additional information
            analysis_result['success'] = True
            analysis_result['filename'] = file.filename
            analysis_result['analysis_time'] = f"{time.time() - start_time:.2f} seconds"
            analysis_result['nlp_available'] = NLP_AVAILABLE
            
            # Get recommendations
            analysis_result['recommendations'] = analyzer.get_recommendations(analysis_result)
            
            print(f"Returning successful result: {analysis_result}")
            return jsonify(analysis_result)
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file.name)
                print(f"Temporary file cleaned up: {temp_file.name}")
            except Exception as cleanup_error:
                print(f"Cleanup error: {cleanup_error}")
        
    except Exception as e:
        print(f"EXCEPTION in analyze_pcap: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": f"Analysis failed: {str(e)}"})

if __name__ == "__main__":
    app.run()
