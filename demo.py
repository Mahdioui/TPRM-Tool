#!/usr/bin/env python3
"""
PCAP Security Analyzer - Demo Script
Demonstrates the capabilities of the PCAP analyzer
"""

import json
import os
import sys

def print_banner():
    """Print application banner"""
    print("🔒 PCAP Security Analyzer - Demo")
    print("=" * 50)
    print()

def demo_analysis():
    """Demonstrate analysis capabilities"""
    print("📊 Analysis Capabilities:")
    print("  • Protocol Detection (IPv4, IPv6, TCP, UDP, ICMP, ARP)")
    print("  • Deep Packet Inspection")
    print("  • Connection Tracking & Analysis")
    print("  • Threat Detection (60+ patterns)")
    print("  • NLP-based Content Analysis")
    print("  • Encryption Detection (Entropy Analysis)")
    print("  • Executable Content Detection")
    print("  • Risk Scoring (0-100)")
    print("  • Professional PDF Reports")
    print()

def demo_threat_patterns():
    """Show threat detection patterns"""
    print("🚨 Threat Detection Patterns:")
    print("  • Malware Indicators:")
    print("    - Command execution (cmd.exe, PowerShell, bash)")
    print("    - File operations (.exe, .bat, .ps1)")
    print("    - Suspicious URLs and domains")
    print("  • Data Exfiltration:")
    print("    - API endpoint scanning")
    print("    - Sensitive data patterns")
    print("    - Unusual transfer patterns")
    print("  • Network Scanning:")
    print("    - Port scanning detection")
    print("    - Host discovery patterns")
    print("    - Service enumeration")
    print("  • Exploitation Attempts:")
    print("    - SQL injection, XSS, command injection")
    print("    - Buffer overflow patterns")
    print("    - Authentication bypass")
    print()

def demo_features():
    """Show application features"""
    print("✨ Application Features:")
    print("  • Modern Web Interface")
    print("  • Real-time Analysis Updates")
    print("  • Interactive Dashboards")
    print("  • Traffic Metrics Visualization")
    print("  • Protocol Analysis Charts")
    print("  • Connection Analysis")
    print("  • Top IP Addresses & Ports")
    print("  • Threat Categorization")
    print("  • Security Recommendations")
    print("  • Export Capabilities (PDF/JSON)")
    print()

def demo_usage():
    """Show usage instructions"""
    print("🚀 How to Use:")
    print("  1. Start the application:")
    print("     python start.py")
    print("     # or on Windows:")
    print("     start.bat")
    print()
    print("  2. Open browser to http://localhost:5000")
    print("  3. Upload a PCAP file (.pcap or .pcapng)")
    print("  4. View comprehensive analysis results")
    print("  5. Download PDF reports or JSON data")
    print()

def demo_samples():
    """Show sample files"""
    print("📁 Sample Files:")
    samples_dir = "samples"
    if os.path.exists(samples_dir):
        print(f"  • Located in '{samples_dir}/' directory:")
        for file in os.listdir(samples_dir):
            if file.endswith('.pcap') or file.endswith('.pcapng'):
                print(f"    - {file}")
    else:
        print("  • No sample files found")
        print("  • Download samples from:")
        print("    - Wireshark Sample Captures")
        print("    - NetResec Pcap Files")
        print("    - DSI Toolkit Samples")
    print()

def main():
    """Main demo function"""
    print_banner()
    demo_analysis()
    demo_threat_patterns()
    demo_features()
    demo_usage()
    demo_samples()
    
    print("🎯 Ready to analyze PCAP files!")
    print("   Run 'python start.py' to begin")

if __name__ == "__main__":
    main()
