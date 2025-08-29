# 🔒 PCAP Security Analyzer

A comprehensive network traffic analysis tool that combines advanced packet inspection, threat detection, and machine learning to identify security threats in PCAP files.

## 🌟 Features

### **Advanced Packet Analysis**
- **Protocol Detection**: IPv4, IPv6, TCP, UDP, ICMP, ARP, and custom protocols
- **Deep Packet Inspection**: Header analysis, payload examination, and traffic pattern recognition
- **Connection Tracking**: Source/destination IP mapping, port analysis, and session reconstruction

### **Threat Detection Engine**
- **60+ Regex Patterns**: Malware signatures, data exfiltration, network scanning, exploitation attempts
- **NLP Analysis**: Natural language processing for suspicious content detection
- **Behavioral Analysis**: Anomaly detection, traffic pattern analysis, and risk scoring
- **Encryption Detection**: Shannon entropy calculation for encrypted traffic identification
- **Executable Detection**: PE, ELF, Mach-O, Java class, and script signature recognition

### **Security Intelligence**
- **Risk Scoring**: Comprehensive 0-100 risk assessment based on multiple factors
- **Threat Categorization**: Organized threat classification with detailed descriptions
- **Security Recommendations**: Actionable security guidance based on analysis results
- **Compliance Reporting**: Professional PDF reports for security audits and documentation

### **Professional Interface**
- **Modern Web UI**: Responsive design with real-time analysis updates
- **Interactive Dashboards**: Traffic metrics, protocol analysis, and threat visualization
- **Export Capabilities**: PDF reports and JSON data export for further analysis

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/pcap-analyzer.git
   cd pcap-analyzer
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
pcap-analyzer/
├── api/                    # Main application directory
│   └── index.py           # Flask application with PCAP analyzer
├── samples/                # Sample PCAP files for testing
│   ├── sample_http_traffic.pcap
│   └── sample_dns_traffic.pcap
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore rules
├── LICENSE                 # Project license
└── README.md              # This file
```

## 🔍 Sample PCAP Files

For testing and demonstration purposes, we've included sample PCAP files in the `samples/` directory:

- **`sample_http_traffic.pcap`**: HTTP web traffic for basic protocol analysis
- **`sample_dns_traffic.pcap`**: DNS queries and responses for network analysis

### Additional Sample Sources

For more comprehensive testing, you can download sample PCAP files from:

- **[Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)**: Official Wireshark sample files
- **[NetResec Pcap Files](https://www.netresec.com/?page=PcapFiles)**: Network security research samples
- **[DSI Toolkit Samples](https://github.com/defenxor/dsi-toolkit/tree/master/samples)**: Digital forensics samples

## 📊 Analysis Capabilities

### **Protocol Analysis**
- **Network Layer**: IP version detection, fragmentation analysis, TTL examination
- **Transport Layer**: TCP/UDP port analysis, connection state tracking, retransmission detection
- **Application Layer**: HTTP header analysis, DNS query examination, custom protocol support

### **Threat Detection Categories**
1. **Malware Indicators**
   - Command execution patterns (cmd.exe, PowerShell, bash)
   - Suspicious file operations and downloads
   - Malicious URL and domain patterns

2. **Data Exfiltration**
   - API endpoint scanning and data extraction
   - Sensitive data patterns (passwords, credit cards, SSNs)
   - Unusual data transfer patterns

3. **Network Scanning**
   - Port scanning and host discovery
   - Service enumeration and vulnerability probing
   - Network reconnaissance activities

4. **Exploitation Attempts**
   - SQL injection, XSS, and command injection patterns
   - Buffer overflow and format string attacks
   - Authentication bypass attempts

### **Advanced Analytics**
- **Entropy Analysis**: Encryption and obfuscation detection
- **Behavioral Patterns**: Traffic flow analysis and anomaly detection
- **Risk Assessment**: Multi-factor security scoring algorithm
- **Threat Correlation**: Pattern matching across multiple analysis layers

## 🛡️ Security Features

### **Threat Intelligence Integration**
- **Pattern Matching**: 60+ regex patterns for known attack signatures
- **Behavioral Analysis**: Machine learning-based anomaly detection
- **Risk Scoring**: Comprehensive security assessment algorithm
- **Real-time Updates**: Dynamic threat pattern updates

### **Compliance & Reporting**
- **Professional PDF Reports**: Executive summaries and technical details
- **JSON Export**: Raw data for SIEM integration and further analysis
- **Audit Trail**: Complete analysis history and findings documentation
- **Customizable Outputs**: Configurable report formats and content

## 🔧 Configuration

### **Environment Variables**
```bash
# Optional: Set Flask environment
export FLASK_ENV=development
export FLASK_DEBUG=1
```

### **Customization**
- **Threat Patterns**: Modify `threat_patterns` in `PcapAnalyzer` class
- **Risk Scoring**: Adjust weights in `_calculate_enhanced_risk_score` method
- **Report Templates**: Customize PDF generation in `generate_pdf` function

## 📈 Performance

- **File Size Support**: Up to 16MB PCAP files
- **Processing Speed**: Optimized for large packet captures
- **Memory Efficiency**: Stream-based processing with minimal memory footprint
- **Scalability**: Modular architecture for easy performance enhancements

## 🧪 Testing

### **Unit Tests**
```bash
# Run basic tests
python -m pytest tests/
```

### **Sample Data Testing**
1. Upload sample PCAP files from the `samples/` directory
2. Verify protocol detection and threat analysis
3. Test PDF report generation
4. Validate risk scoring algorithms

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### **Development Setup**
```bash
# Clone and setup development environment
git clone https://github.com/yourusername/pcap-analyzer.git
cd pcap-analyzer
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

## 📚 API Documentation

### **Endpoints**

- **`GET /`**: Main web interface
- **`POST /analyze`**: PCAP file analysis
- **`POST /generate-pdf`**: PDF report generation
- **`GET /health`**: Health check endpoint
- **`GET /test`**: Test endpoint for verification

### **Request/Response Format**
```json
{
  "success": true,
  "packet_count": 1234,
  "risk_score": 75,
  "threats": ["Suspicious port: 4444->80"],
  "protocols": {"TCP": 1000, "UDP": 234},
  "recommendations": ["Review firewall rules"]
}
```

## 🏗️ Architecture

### **Core Components**
1. **PcapAnalyzer**: Main analysis engine with threat detection
2. **Flask Web Server**: RESTful API and web interface
3. **Report Generator**: PDF creation and export functionality
4. **Frontend Interface**: Modern web UI with real-time updates

### **Technology Stack**
- **Backend**: Python 3.8+, Flask, reportlab
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Analysis**: Custom PCAP parser, regex engine, NLP integration
- **Reporting**: PDF generation, JSON export, data visualization

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Wireshark Community**: For PCAP format documentation
- **Security Researchers**: For threat pattern contributions
- **Open Source Contributors**: For various libraries and tools

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/pcap-analyzer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/pcap-analyzer/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/pcap-analyzer/wiki)

## 🔮 Roadmap

- [ ] **Machine Learning Integration**: Enhanced anomaly detection
- [ ] **Real-time Monitoring**: Live network traffic analysis
- [ ] **Threat Intelligence**: Integration with external threat feeds
- [ ] **Cloud Deployment**: AWS/Azure deployment options
- [ ] **Mobile App**: iOS/Android companion applications

---

**Made with ❤️ for the cybersecurity community**

*This tool is designed for educational and research purposes. Always ensure you have proper authorization before analyzing network traffic.*
