# 🔒 PCAP Security Analyzer

A professional network traffic analysis and threat detection platform that combines **regex pattern matching** and **NLP-based analysis** for comprehensive security insights.

## ✨ Features

- **📊 Comprehensive PCAP Analysis**: Deep packet inspection with protocol identification
- **🔍 Regex Threat Detection**: Advanced pattern matching for malware indicators
- **🧠 NLP Threat Analysis**: Intelligent content analysis and behavioral detection
- **🚨 Real-time Threat Detection**: Instant identification of suspicious activities
- **📈 Risk Scoring & Analytics**: Intelligent risk assessment with detailed metrics
- **🔐 Professional Reporting**: Comprehensive security reports with recommendations

## 🛠️ Technology Stack

- **Backend**: Python Flask
- **PCAP Parsing**: Native Python struct module
- **Regex Engine**: Python re module
- **NLP Analysis**: Custom text analysis without external dependencies
- **Frontend**: HTML/CSS/JavaScript with modern UI

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- pip (Python package installer)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Mahdioui/TPRM-Tool.git
   cd TPRM-Tool
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   cd api
   python index.py
   ```

4. **Open your browser**
   Navigate to `http://localhost:5000`

## 📁 Project Structure

```
pcapAnalyzer/
├── api/
│   ├── index.py          # Main Flask application
│   └── nlp_utils.py      # NLP analysis utilities
├── index.html            # Professional landing page
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## 🔧 Usage

### 1. Upload PCAP File
- Navigate to the web interface
- Click "Choose File" and select your `.pcap` or `.pcapng` file
- Click "🚀 Analyze PCAP File"

### 2. View Analysis Results
The analyzer provides:
- **Packet Statistics**: Total packets, bytes, protocols
- **Threat Analysis**: Regex and NLP-based threat detection
- **Connection Analysis**: IP addresses, ports, connection patterns
- **Risk Assessment**: Comprehensive security scoring
- **Recommendations**: Actionable security guidance

### 3. Understanding Results

#### Threat Categories
- **🚨 Regex Threats**: Pattern-based malware detection
- **🧠 NLP Threats**: Intelligent content analysis
- **🔐 Suspicious Payloads**: Encrypted/compressed content detection

#### Risk Scoring (0-100)
- **🟢 LOW (0-30)**: Standard security practices sufficient
- **🟡 MEDIUM (31-50)**: Monitor for suspicious activity
- **⚠️ HIGH (51-70)**: Security assessment recommended
- **🚨 CRITICAL (71-100)**: Immediate security review required

## 🔍 Supported Protocols

- **Ethernet**: Frame parsing and type detection
- **IPv4**: Address extraction and protocol identification
- **TCP**: Port analysis and payload inspection
- **UDP**: DNS query analysis
- **ICMP**: Ping detection
- **ARP**: Address resolution protocol

## 🧠 NLP Analysis Features

- **Keyword Detection**: Malicious terms and patterns
- **Command Analysis**: Suspicious shell commands
- **Data Exfiltration**: Upload/download patterns
- **Scanning Activity**: Network reconnaissance detection
- **Entropy Analysis**: Encrypted traffic identification
- **Entity Extraction**: IPs, URLs, domains, emails

## 🚨 Threat Detection Patterns

### Regex Patterns
- Malware indicators: `cmd.exe`, `powershell`, `wget`, `curl`
- Suspicious commands: `python -c`, `perl -e`, `bash -c`
- File operations: `.exe download`, `.bat execute`

### NLP Analysis
- Malicious keywords: malware, virus, trojan, backdoor
- Suspicious activities: hack, exploit, vulnerability, breach
- Command patterns: download, upload, transfer, exfiltrate

## 📊 API Endpoints

- **`/`**: Main web interface
- **`/analyze`**: PCAP file analysis (POST)
- **`/health`**: Health check endpoint
- **`/test`**: Basic functionality test

## 🔧 Customization

### Adding New Threat Patterns
Edit `api/index.py` in the `PcapAnalyzer.__init__()` method:

```python
self.threat_patterns = {
    'suspicious_ports': [22, 23, 3389, 5900, 8080, 8443, 4444, 31337, 6667],
    'malware_patterns': [
        r'cmd\.exe', r'powershell', r'wget', r'curl',
        # Add your custom patterns here
        r'your_pattern_here'
    ]
}
```

### Extending NLP Analysis
Modify `api/nlp_utils.py` to add new analysis methods:

```python
def analyze_custom_pattern(self, text):
    # Add your custom NLP analysis logic
    pass
```

## 🐛 Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   # Change port in index.py
   app.run(port=5001)
   ```

2. **PCAP file not recognized**
   - Ensure file has `.pcap` or `.pcapng` extension
   - Verify file is not corrupted
   - Check file size (max 16MB)

3. **Import errors**
   ```bash
   pip install -r requirements.txt
   ```

### Debug Mode
Enable debug logging by modifying `index.py`:

```python
if __name__ == "__main__":
    app.run(debug=True, port=5000)
```

## 📈 Performance

- **File Size**: Supports up to 16MB PCAP files
- **Processing Speed**: ~1000 packets/second on standard hardware
- **Memory Usage**: Efficient packet-by-packet processing
- **Scalability**: Can handle large capture files with streaming

## 🔒 Security Features

- **Input Validation**: File type and size restrictions
- **Temporary File Handling**: Secure file processing
- **Error Handling**: Graceful failure without information leakage
- **Rate Limiting**: Built-in request throttling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is open source and available under the MIT License.

## 🆘 Support

For issues and questions:
- Check the troubleshooting section
- Review the code comments
- Open an issue on GitHub

## 🎯 Roadmap

- [ ] Support for more PCAP formats
- [ ] Enhanced machine learning models
- [ ] Real-time network monitoring
- [ ] Integration with SIEM systems
- [ ] Advanced visualization dashboards

---

**Built with ❤️ for Network Security Professionals**
