#!/usr/bin/env python3
"""
PCAP Security Analyzer - Startup Script
Simple launcher for the PCAP analysis application
"""

import os
import sys
import subprocess
import webbrowser
import time

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import flask
        import reportlab
        print("✅ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def start_application():
    """Start the Flask application"""
    print("🚀 Starting PCAP Security Analyzer...")
    
    # Change to api directory
    api_dir = os.path.join(os.path.dirname(__file__), 'api')
    if not os.path.exists(api_dir):
        print("❌ Error: api directory not found")
        return False
    
    os.chdir(api_dir)
    
    # Start the Flask app
    try:
        print("📡 Application starting on http://localhost:5000")
        print("🌐 Opening browser in 3 seconds...")
        
        # Wait a bit for the server to start
        time.sleep(3)
        
        # Open browser
        webbrowser.open('http://localhost:5000')
        
        # Start the Flask application
        subprocess.run([sys.executable, 'index.py'])
        
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        return False
    
    return True

def main():
    """Main function"""
    print("🔒 PCAP Security Analyzer")
    print("=" * 40)
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Start application
    start_application()

if __name__ == "__main__":
    main()
