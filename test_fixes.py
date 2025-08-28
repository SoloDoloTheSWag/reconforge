#!/usr/bin/env python3
"""
Test script to verify terminal interface fixes
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from utils.database import ReconForgeDB

def test_database_methods():
    """Test database method fixes"""
    print("🔍 Testing database methods...")
    
    try:
        db = ReconForgeDB()
        
        # Test creating a scan
        scan_id = db.create_scan("test.com", "test_scan", {})
        print(f"✅ create_scan works - ID: {scan_id}")
        
        # Test complete_scan method
        db.complete_scan(scan_id, 5, "subdomain_discovery")
        print("✅ complete_scan works")
        
        # Test fail_scan method  
        scan_id2 = db.create_scan("test2.com", "test_scan", {})
        db.fail_scan(scan_id2, "Test error")
        print("✅ fail_scan works")
        
        # Test add_vulnerability_simple
        scan_id3 = db.create_scan("test3.com", "vulnerability_scan", {})
        db.add_vulnerability_simple(scan_id3, "test.com", "xss", "high", "Test XSS", "Test description", "http://test.com")
        print("✅ add_vulnerability_simple works")
        
        print("🎉 All database methods working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_import_terminal():
    """Test terminal interface import"""
    print("🔍 Testing terminal interface import...")
    
    try:
        from interface.terminal import ReconForgeTerminal
        terminal = ReconForgeTerminal()
        print("✅ Terminal interface imports successfully")
        
        # Test that all required methods exist
        methods_to_check = [
            'run_comprehensive_scan',
            'run_custom_scanner_selection', 
            'run_ssl_scan',
            'run_web_app_scan',
            'export_vulnerability_results'
        ]
        
        for method in methods_to_check:
            if hasattr(terminal, method):
                print(f"✅ Method {method} exists")
            else:
                print(f"❌ Method {method} missing")
                return False
        
        print("🎉 All terminal methods exist!")
        return True
        
    except Exception as e:
        print(f"❌ Terminal import test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 ReconForge Terminal Interface Fix Tests")
    print("=" * 50)
    
    db_test = test_database_methods()
    print()
    terminal_test = test_import_terminal()
    print()
    
    if db_test and terminal_test:
        print("🎉 ALL TESTS PASSED! Fixes are working correctly.")
        print("👍 You can now test the terminal interface again.")
        return True
    else:
        print("❌ Some tests failed. Check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)