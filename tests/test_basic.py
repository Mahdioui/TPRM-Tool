"""
Basic tests for PCAP Security Analyzer
"""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_imports():
    """Test that all core modules can be imported"""
    try:
        from analyzer import PcapAnalyzer
        print("✅ PcapAnalyzer imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import PcapAnalyzer: {e}")
        return False
    
    try:
        from risk_calculator import RiskCalculator
        print("✅ RiskCalculator imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import RiskCalculator: {e}")
        return False
    
    try:
        from enhanced_report_generator import EnhancedReportGenerator
        print("✅ EnhancedReportGenerator imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import EnhancedReportGenerator: {e}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic functionality of core classes"""
    try:
        from risk_calculator import RiskLevel
        
        # Test RiskLevel enum
        assert RiskLevel.MINIMAL.value == 1
        assert RiskLevel.CRITICAL.value == 5
        print("✅ RiskLevel enum working correctly")
        
        return True
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def test_file_structure():
    """Test that required files exist"""
    required_files = [
        'src/analyzer.py',
        'src/risk_calculator.py',
        'src/enhanced_report_generator.py',
        'web_interface.py',
        'main.py',
        'requirements.txt',
        'vercel.json'
    ]
    
    for file_path in required_files:
        if not os.path.exists(file_path):
            print(f"❌ Required file missing: {file_path}")
            return False
    
    print("✅ All required files present")
    return True

if __name__ == "__main__":
    print("🧪 Running basic tests for PCAP Security Analyzer")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_basic_functionality,
        test_file_structure
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"❌ Test {test.__name__} failed")
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)
