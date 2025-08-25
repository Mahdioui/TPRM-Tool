from flask import Flask, jsonify, request
import tempfile
import os
import time

# Import our simple PCAP parser
from simple_pcap_parser import SimplePcapParser

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize simple PCAP parser
analyzer = SimplePcapParser()

# HTML template for the web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>PCAP Security Analyzer</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }
        .upload-section { text-align: center; padding: 30px; border: 2px dashed #3498db; border-radius: 10px; margin: 20px 0; }
        .upload-section:hover { border-color: #2980b9; background: #f8f9fa; }
        input[type="file"] { margin: 20px 0; }
        button { background: #3498db; color: white; padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #2980b9; }
        .results { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .error { color: #e74c3c; background: #fdf2f2; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .success { color: #27ae60; background: #f0f9f0; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .warning { color: #f39c12; background: #fef9e7; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .info { color: #3498db; background: #ebf3fd; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .threat-list { background: #fff5f5; border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; }
        .recommendations { background: #f0f9ff; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 PCAP Security Analyzer</h1>
        
        <div class="upload-section">
            <h3>Upload PCAP File for Security Analysis</h3>
            <form id="uploadForm" enctype="multipart/form-data">
                <input type="file" name="file" accept=".pcap,.pcapng" required>
                <br>
                <button type="submit">Analyze PCAP</button>
            </form>
        </div>
        
        <div id="results"></div>
    </div>

    <script>
        document.getElementById('uploadForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const resultsDiv = document.getElementById('results');
            
            resultsDiv.innerHTML = '<div class="info">🔍 Analyzing PCAP file for security threats...</div>';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // Create comprehensive results display
                    let html = `
                        <div class="success">
                            <h3>🔍 Security Analysis Complete!</h3>
                            <p><strong>File:</strong> ${result.filename}</p>
                            <p><strong>Analysis Time:</strong> ${result.analysis_time}</p>
                        </div>
                        
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-number">${result.packet_count}</div>
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
                    `;
                    
                    // Add protocols
                    if (result.protocols) {
                        html += `
                            <div class="info">
                                <h4>📊 Protocols Detected:</h4>
                                <p>${Object.entries(result.protocols).map(([proto, count]) => `${proto}: ${count}`).join(', ')}</p>
                            </div>
                        `;
                    }
                    
                    // Add threats if any
                    if (result.threats && result.threats.length > 0) {
                        html += `
                            <div class="threat-list">
                                <h4>⚠️ Security Threats Detected:</h4>
                                <ul>
                                    ${result.threats.map(threat => `<li>${threat}</li>`).join('')}
                                </ul>
                            </div>
                        `;
                    } else {
                        html += '<div class="success"><h4>✅ No immediate threats detected</h4></div>';
                    }
                    
                    // Add recommendations
                    if (result.recommendations) {
                        html += `
                            <div class="recommendations">
                                <h4>💡 Security Recommendations:</h4>
                                <ul>
                                    ${result.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                                </ul>
                            </div>
                        `;
                    }
                    
                    resultsDiv.innerHTML = html;
                } else {
                    resultsDiv.innerHTML = `<div class="error">❌ Error: ${result.error}</div>`;
                }
            } catch (error) {
                resultsDiv.innerHTML = `<div class="error">❌ Error: ${error.message}</div>`;
            }
        });
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
            # Analyze the PCAP file using simple parser
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
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    app.run()
