from flask import Flask, jsonify, request, send_file
import tempfile
import os
import time
import struct
import json
from collections import defaultdict
import io
import re

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
        """Simple but working PCAP analysis"""
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
                
                # Initialize counters
                protocols = defaultdict(int)
                ips = defaultdict(int)
                ports = defaultdict(int)
                threats = []
                connections = []
                packet_count = 0
                total_bytes = 0
                
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
                    
                    # Basic packet analysis
                    if len(packet_data) >= 14:
                        eth_type = struct.unpack(f'{byte_order}H', packet_data[12:14])[0]
                        
                        if eth_type == 0x0800 and len(packet_data) >= 34:  # IPv4
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
                                        src_port = struct.unpack(f'{byte_order}H', packet_data[34:36])[0]
                                        dst_port = struct.unpack(f'{byte_order}H', packet_data[36:38])[0]
                                        ports[src_port] += 1
                                        ports[dst_port] += 1
                                        
                                        # Check for suspicious ports
                                        if src_port in self.threat_patterns['suspicious_ports'] or \
                                           dst_port in self.threat_patterns['suspicious_ports']:
                                            threats.append(f"Suspicious port: {src_port}->{dst_port}")
                                        
                                        # Track connections
                                        connections.append({
                                            'src_ip': src_ip,
                                            'dst_ip': dst_ip,
                                            'src_port': src_port,
                                            'dst_port': dst_port,
                                            'protocol': 'TCP'
                                        })
                                
                                elif ip_proto == 17:  # UDP
                                    protocols['UDP'] += 1
                                    if len(packet_data) >= 38:
                                        src_port = struct.unpack(f'{byte_order}H', packet_data[34:36])[0]
                                        dst_port = struct.unpack(f'{byte_order}H', packet_data[36:38])[0]
                                        ports[src_port] += 1
                                        ports[dst_port] += 1
                                
                                elif ip_proto == 1:  # ICMP
                                    protocols['ICMP'] += 1
                        
                        elif eth_type == 0x0806:  # ARP
                            protocols['ARP'] += 1
                
                # Calculate metrics
                duration = 0  # Simplified for now
                avg_packet_size = total_bytes / packet_count if packet_count > 0 else 0
                packets_per_second = packet_count / duration if duration > 0 else 0
                
                # Calculate risk score
                risk_score = self._calculate_risk_score(packet_count, protocols, threats, ports, ips)
                
                # Get top talkers and ports
                top_ips = dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10])
                top_ports = dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10])
                
                # Connection analysis
                connection_analysis = self._analyze_connections(connections, ips)
                
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
                    'connections': connections[:100],
                    'risk_score': risk_score,
                    'top_ips': top_ips,
                    'top_ports': top_ports,
                    'connection_analysis': connection_analysis,
                    'file_info': {
                        'version': f"{version_major}.{version_minor}",
                        'total_size': f"{packet_count} packets ({total_bytes:,} bytes)"
                    }
                }
                
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}
    
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
    
    def _calculate_risk_score(self, packet_count, protocols, threats, ports, ips):
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
        """Get security recommendations"""
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
            
            resultsDiv.innerHTML = '<div class="loading"><div class="spinner"></div><p>🔍 Analyzing PCAP file...</p></div>';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    displayResults(result);
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
                
                <div class="section">
                    <h3>📊 Protocol Analysis</h3>
                    <p><strong>Detected Protocols:</strong> ${Object.entries(result.protocols).map(([proto, count]) => `${proto}: ${count.toLocaleString()}`).join(', ')}</p>
                </div>
                
                <div class="section">
                    <h3>🏠 Top IP Addresses</h3>
                    <p>${Object.entries(result.top_ips).map(([ip, count]) => `${ip}: ${count.toLocaleString()} packets`).join(', ')}</p>
                </div>
                
                <div class="section">
                    <h3>🔌 Top Ports</h3>
                    <p>${Object.entries(result.top_ports).map(([port, count]) => `Port ${port}: ${count.toLocaleString()} packets`).join(', ')}</p>
                </div>
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
            
            resultsDiv.innerHTML = html;
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

if __name__ == "__main__":
    app.run()
