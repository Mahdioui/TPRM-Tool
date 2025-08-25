from flask import Flask, jsonify, request, send_file
import tempfile
import os
import time
import struct
import json
from collections import defaultdict
import io

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

class PcapAnalyzer:
    def __init__(self):
        self.threat_patterns = {
            'suspicious_ports': [22, 23, 3389, 5900, 8080, 8443, 4444, 31337, 6667],
            'suspicious_protocols': ['HTTP', 'FTP', 'TELNET']
        }
    
    def analyze_pcap(self, file_path):
        """Analyze PCAP file and return comprehensive security insights"""
        try:
            with open(file_path, 'rb') as f:
                # Read PCAP header (24 bytes)
                header = f.read(24)
                if len(header) < 24:
                    return {"error": "Invalid PCAP file - header too short"}
                
                # Check for all possible PCAP magic numbers
                magic = struct.unpack('>I', header[0:4])[0]
                magic_le = struct.unpack('<I', header[0:4])[0]
                
                # Valid PCAP magic numbers
                valid_magics = [
                    0xa1b2c3d4,  # Big-endian
                    0xd4c3b2a1,  # Little-endian
                    0xa1b23c4d,  # Big-endian with nanosecond precision
                    0x4d3cb2a1   # Little-endian with nanosecond precision
                ]
                
                if magic not in valid_magics and magic_le not in valid_magics:
                    return {"error": f"Invalid PCAP file - unsupported magic number: 0x{magic:08x}"}
                
                # Determine byte order and precision
                if magic in valid_magics:
                    byte_order = '>'
                    precision = 'microsecond' if magic in [0xa1b2c3d4, 0xd4c3b2a1] else 'nanosecond'
                else:
                    byte_order = '<'
                    precision = 'microsecond' if magic_le in [0xa1b2c3d4, 0xd4c3b2a1] else 'nanosecond'
                
                # Parse header with correct byte order
                version_major = struct.unpack(f'{byte_order}H', header[4:6])[0]
                version_minor = struct.unpack(f'{byte_order}H', header[6:8])[0]
                timezone = struct.unpack(f'{byte_order}I', header[8:12])[0]
                sigfigs = struct.unpack(f'{byte_order}I', header[12:16])[0]
                snaplen = struct.unpack(f'{byte_order}I', header[16:20])[0]
                linktype = struct.unpack(f'{byte_order}I', header[20:24])[0]
                
                # Initialize analysis
                protocols = defaultdict(int)
                ips = defaultdict(int)
                ports = defaultdict(int)
                threats = []
                connections = []
                
                packet_count = 0
                total_bytes = 0
                
                while True:
                    # Read packet header
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break
                    
                    # Parse packet header with correct byte order
                    ts_sec = struct.unpack(f'{byte_order}I', pkt_header[0:4])[0]
                    if precision == 'nanosecond':
                        ts_usec = struct.unpack(f'{byte_order}I', pkt_header[4:8])[0]
                    else:
                        ts_usec = struct.unpack(f'{byte_order}I', pkt_header[4:8])[0]
                    
                    incl_len = struct.unpack(f'{byte_order}I', pkt_header[8:12])[0]
                    orig_len = struct.unpack(f'{byte_order}I', pkt_header[12:16])[0]
                    
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
                                            threats.append(f"Suspicious port usage: {src_port}->{dst_port}")
                                        
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
                
                # Calculate risk score
                risk_score = self._calculate_risk_score(packet_count, protocols, threats, ports)
                
                # Get top talkers and ports
                top_ips = dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10])
                top_ports = dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10])
                
                return {
                    'packet_count': packet_count,
                    'total_bytes': total_bytes,
                    'protocols': dict(protocols),
                    'ips': dict(ips),
                    'ports': dict(ports),
                    'threats': threats,
                    'connections': connections[:100],  # Limit to first 100 connections
                    'risk_score': risk_score,
                    'top_ips': top_ips,
                    'top_ports': top_ports,
                    'file_info': {
                        'version': f"{version_major}.{version_minor}",
                        'byte_order': 'Big-endian' if byte_order == '>' else 'Little-endian',
                        'precision': precision,
                        'link_type': linktype,
                        'total_size': f"{packet_count} packets ({total_bytes:,} bytes)"
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

# Initialize analyzer
analyzer = PcapAnalyzer()

# HTML template with enhanced dashboard
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
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        .upload-section { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); text-align: center; margin: 30px 0; }
        .upload-section h3 { color: #2c3e50; margin-bottom: 20px; }
        .file-input { border: 2px dashed #3498db; border-radius: 10px; padding: 40px; margin: 20px 0; transition: all 0.3s; }
        .file-input:hover { border-color: #2980b9; background: #f8f9fa; }
        .file-input input[type="file"] { margin: 20px 0; }
        .analyze-btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 40px; border: none; border-radius: 25px; cursor: pointer; font-size: 16px; font-weight: 500; transition: all 0.3s; }
        .analyze-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        
        .dashboard { display: none; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 25px; margin: 30px 0; }
        .stat-card { background: white; padding: 25px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); text-align: center; transition: transform 0.3s; }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-number { font-size: 2.5em; font-weight: bold; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .stat-label { color: #7f8c8d; margin-top: 10px; font-size: 1.1em; }
        
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
        
        .loading { text-align: center; padding: 40px; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
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
                </div>
                
                <div class="section">
                    <h3>📊 Protocol Analysis</h3>
                    <p><strong>Detected Protocols:</strong> ${Object.entries(result.protocols).map(([proto, count]) => `${proto}: ${count.toLocaleString()}`).join(', ')}</p>
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
