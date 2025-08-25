#!/usr/bin/env python3
"""
PCAP Security Analyzer - Easy Startup Script
Professional Network Security Analysis Tool
"""

import sys
import os
import subprocess
import webbrowser
import time
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import scapy
        import flask
        return True
    except ImportError:
        return False

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing required dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return False

def start_web_interface():
    """Start the web interface"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      PCAP Security Analyzer - Starting                      ║
║                        Professional Network Analysis                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 🌐 Web Interface: http://localhost:5000                                     ║
║ 📁 Upload PCAP files for comprehensive security analysis                    ║
║ 📊 Get interactive dashboards and professional reports                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Start web interface
    try:
        # Import and run the web interface
        sys.path.insert(0, os.path.dirname(__file__))
        
        # Delay browser opening to let server start
        def open_browser():
            time.sleep(2)
            webbrowser.open('http://localhost:5000')
        
        import threading
        browser_thread = threading.Thread(target=open_browser)
        browser_thread.daemon = True
        browser_thread.start()
        
        # Start the web server
        from web_interface import app
        app.run(host='0.0.0.0', port=5000, debug=False)
        
    except ImportError as e:
        print(f"❌ Failed to start web interface: {e}")
        print("💡 Try installing dependencies with: pip install -r requirements.txt")
        return False
    except KeyboardInterrupt:
        print("\n👋 Analyzer stopped by user")
        return True
    except Exception as e:
        print(f"❌ Error starting analyzer: {e}")
        return False

def main():
    """Main startup function"""
    print("🔍 PCAP Security Analyzer")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("web_interface.py").exists():
        print("❌ Please run this script from the PCAP Analyzer directory")
        return 1
    
    # Check dependencies
    if not check_dependencies():
        print("⚠️  Required dependencies not found")
        install_choice = input("📦 Install dependencies now? (y/n): ")
        if install_choice.lower() in ['y', 'yes']:
            if not install_dependencies():
                return 1
        else:
            print("💡 Install dependencies manually: pip install -r requirements.txt")
            return 1
    
    # Start the analyzer
    if start_web_interface():
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())
