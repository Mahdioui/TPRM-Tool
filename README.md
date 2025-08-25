# 🛡️ PCAP Security Analyzer - Professional Edition

A comprehensive, production-ready network security analysis tool that provides detailed PCAP analysis, threat detection, risk assessment, and professional PDF reporting with TPRM recommendations.

## ✨ Features

### 🔍 **PCAP Analysis & Network Intelligence**
- **Advanced Packet Analysis**: Deep packet inspection using Scapy and PyShark
- **Flow Analysis**: Network flow detection and conversation tracking
- **Protocol Intelligence**: Comprehensive protocol analysis and statistics
- **Traffic Pattern Recognition**: Behavioral analysis and anomaly detection

### 🚨 **Threat Detection & Security Intelligence**
- **Regex-based Detection**: Centralized threat signature matching
- **NLP Payload Analysis**: AI-powered content analysis using spaCy and NLTK
- **Malware Indicators**: Detection of suspicious patterns and behaviors
- **Real-time Alerts**: Immediate threat notification and categorization

### 📊 **Risk Assessment & Compliance**
- **Comprehensive Risk Scoring**: 0-100 risk assessment with detailed breakdown
- **ISO/IEC 27001 Mapping**: Regulatory compliance and control mapping
- **NIST Cybersecurity Framework**: Industry-standard security assessment
- **OWASP Top 10 Integration**: Web application security analysis

### 📈 **Professional Reporting & Analytics**
- **Executive Dashboards**: KPI-driven security metrics and visualizations
- **Professional PDF Reports**: Corporate-grade reports with charts and analysis
- **TPRM Recommendations**: Third-party risk management insights
- **Compliance Mapping**: Detailed regulatory framework alignment

### 🌐 **Modern Web Interface**
- **Professional Dashboard**: Clean, aesthetic interface with minimal emojis
- **Real-time Analytics**: Live progress tracking and result visualization
- **Responsive Design**: Mobile-friendly interface with modern UI/UX
- **Interactive Charts**: Dynamic visualizations using matplotlib and seaborn

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Wireshark (optional, for enhanced PCAP support)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/pcap-security-analyzer.git
   cd pcap-security-analyzer
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python web_interface.py
   ```

4. **Access the interface**
   - Open your browser and go to `http://localhost:5000`
   - Upload a PCAP file and start analysis

## 📁 Project Structure

```
pcap-security-analyzer/
├── src/                          # Core analysis modules
│   ├── analyzer.py              # PCAP parsing and analysis
│   ├── extractor.py             # Connection and flow extraction
│   ├── regex_utils.py           # Threat detection rules
│   ├── nlp_utils.py             # Natural language processing
│   ├── risk_calculator.py       # Risk assessment engine
│   ├── enhanced_report_generator.py  # Professional PDF reports
│   └── report_generator.py      # Basic report generation
├── web_interface.py             # Main Flask web application
├── main.py                      # CLI interface
├── requirements.txt             # Python dependencies
├── vercel.json                  # Vercel deployment configuration
└── README.md                    # This file
```

## 🔧 Usage

### Web Interface (Recommended)
```bash
python web_interface.py
```
- Professional dashboard with real-time analytics
- Upload PCAP files and generate comprehensive reports
- Interactive charts and KPI dashboards

### Command Line Interface
```bash
python main.py --file data/sample.pcap --report output/report.pdf
```

### API Endpoints
- `POST /upload` - Upload PCAP file for analysis
- `GET /progress` - Check analysis progress
- `GET /results` - Get analysis results
- `GET /charts` - Get visualization charts
- `GET /download_report` - Download generated PDF report

## 📊 Risk Assessment Methodology

### Risk Scoring Algorithm
The system uses a comprehensive risk scoring algorithm that considers:

1. **Protocol Security (15%)**: Insecure protocols, encryption status
2. **Connection Anomalies (12%)**: Unusual connection patterns
3. **Traffic Patterns (10%)**: Behavioral analysis and flow characteristics
4. **Port Usage (8%)**: Suspicious port activity and service detection
5. **Payload Threats (20%)**: Content-based threat detection
6. **Injection Attacks (18%)**: SQL injection, XSS, command injection
7. **Malware Indicators (15%)**: Malicious pattern recognition
8. **Data Exfiltration (12%)**: Unusual data transfer patterns

### Compliance Frameworks
- **ISO/IEC 27001**: Information security management
- **NIST CSF**: Cybersecurity framework controls
- **OWASP Top 10**: Web application security
- **MITRE ATT&CK**: Threat modeling and detection

## 🌐 Deployment

### Vercel Deployment

1. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Initial commit: PCAP Security Analyzer"
   git push origin main
   ```

2. **Deploy on Vercel**
   - Connect your GitHub repository to Vercel
   - Vercel will automatically detect the Python configuration
   - Deploy with zero configuration

### Environment Variables
```bash
FLASK_ENV=production
FLASK_DEBUG=false
MAX_CONTENT_LENGTH=100000000  # 100MB max file size
```

## 📈 Performance & Scalability

- **Efficient Processing**: Optimized for large PCAP files (up to 100MB)
- **Background Analysis**: Non-blocking analysis with progress tracking
- **Memory Management**: Efficient memory usage for large datasets
- **Concurrent Processing**: Support for multiple simultaneous analyses

## 🔒 Security Features

- **File Validation**: Secure file upload with type checking
- **Input Sanitization**: Protection against malicious input
- **Access Control**: Secure file handling and processing
- **Audit Logging**: Comprehensive analysis logging and tracking


### Development Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/
```


**Built with ❤️, Salma**
