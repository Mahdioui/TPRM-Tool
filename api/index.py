from flask import Flask, jsonify, request, render_template_string
import os
import tempfile
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

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
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }
        .upload-section { text-align: center; padding: 30px; border: 2px dashed #3498db; border-radius: 10px; margin: 20px 0; }
        .upload-section:hover { border-color: #2980b9; background: #f8f9fa; }
        input[type="file"] { margin: 20px 0; }
        button { background: #3498db; color: white; padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #2980b9; }
        .results { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .error { color: #e74c3c; background: #fdf2f2; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .success { color: #27ae60; background: #f0f9f0; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 PCAP Security Analyzer</h1>
        
        <div class="upload-section">
            <h3>Upload PCAP File for Analysis</h3>
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
            
            resultsDiv.innerHTML = '<div class="success">Analyzing PCAP file...</div>';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    resultsDiv.innerHTML = `
                        <div class="success">
                            <h3>Analysis Complete!</h3>
                            <p><strong>File:</strong> ${result.filename}</p>
                            <p><strong>Packets:</strong> ${result.packet_count}</p>
                            <p><strong>Protocols:</strong> ${result.protocols.join(', ')}</p>
                            <p><strong>Risk Score:</strong> ${result.risk_score}/100</p>
                            <p><strong>Threats Detected:</strong> ${result.threats.length}</p>
                            ${result.threats.length > 0 ? '<p><strong>Threats:</strong> ' + result.threats.join(', ') + '</p>' : ''}
                        </div>
                    `;
                } else {
                    resultsDiv.innerHTML = `<div class="error">Error: ${result.error}</div>`;
                }
            } catch (error) {
                resultsDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
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
        
        # For now, return a mock analysis (we'll add real PCAP analysis next)
        filename = secure_filename(file.filename)
        
        # Mock analysis results
        analysis_result = {
            "success": True,
            "filename": filename,
            "packet_count": 1250,
            "protocols": ["TCP", "HTTP", "DNS"],
            "risk_score": 35,
            "threats": ["Suspicious DNS query", "HTTP traffic on non-standard port"],
            "analysis_time": "2.3 seconds"
        }
        
        return jsonify(analysis_result)
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    app.run()
