#!/usr/bin/env python3
"""
ReconForge Integration Test Suite
Tests core functionality and integration between components
"""

import asyncio
import tempfile
import os
import sys
from pathlib import Path
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))
os.chdir(Path(__file__).parent)

from utils.database import ReconForgeDB
from utils.helpers import DomainValidator, ToolValidator
from utils.logging import setup_logging
from sources.base import SourceManager, SubdomainResult
from sources.passive import get_passive_sources
from scanners.base import ScannerManager, VulnerabilityResult, VulnerabilitySeverity
from pentest.base import PentestManager, PentestResult, ExploitSeverity


class ReconForgeTestSuite:
    """Comprehensive test suite for ReconForge"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
        
        # Setup logging
        setup_logging('INFO', 'logs/test.log')
        
    def test_database(self):
        """Test database functionality"""
        print("🔍 Testing Database...")
        
        try:
            # Test database creation and initialization
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
                db_path = tmp.name
            
            db = ReconForgeDB(db_path)
            
            # Test scan creation
            scan_id = db.create_scan("example.com", "test_scan", {"test": True})
            assert scan_id > 0, "Scan ID should be positive"
            
            # Test scan retrieval
            scan = db.get_scan(scan_id)
            assert scan is not None, "Scan should exist"
            assert scan['target'] == "example.com", "Target should match"
            
            # Test subdomain addition
            db.add_subdomain(scan_id, "www.example.com", ip_address="1.2.3.4", discovery_source="test")
            subdomains = db.get_subdomains(scan_id)
            assert len(subdomains) == 1, "Should have one subdomain"
            
            # Test vulnerability addition
            vuln_id = db.add_vulnerability(scan_id, {
                'subdomain': 'www.example.com',
                'vulnerability_type': 'Test Vuln',
                'severity': 'high',
                'title': 'Test Vulnerability',
                'description': 'This is a test'
            })
            assert vuln_id > 0, "Vulnerability ID should be positive"
            
            vulns = db.get_vulnerabilities(scan_id)
            assert len(vulns) == 1, "Should have one vulnerability"
            
            # Test statistics
            stats = db.get_scan_stats(scan_id)
            assert stats['total_subdomains'] == 1, "Stats should show 1 subdomain"
            assert stats['total_vulnerabilities'] == 1, "Stats should show 1 vulnerability"
            
            # Cleanup
            os.unlink(db_path)
            
            print("✅ Database tests passed")
            self.passed += 1
            
        except Exception as e:
            print(f"❌ Database tests failed: {e}")
            self.failed += 1
            self.errors.append(f"Database: {e}")
    
    def test_domain_validation(self):
        """Test domain validation utilities"""
        print("🔍 Testing Domain Validation...")
        
        try:
            # Valid domains
            valid_domains = [
                "example.com",
                "sub.example.com", 
                "test-site.co.uk",
                "api.v2.example.org"
            ]
            
            for domain in valid_domains:
                assert DomainValidator.is_valid_domain(domain), f"{domain} should be valid"
            
            # Invalid domains
            invalid_domains = [
                "",
                "invalid",
                "http://example.com", 
                "example..com",
                "-example.com"
            ]
            
            for domain in invalid_domains:
                result = DomainValidator.is_valid_domain(domain)
                if result:  # If validation unexpectedly passed
                    print(f"DEBUG: '{domain}' was considered valid when it should be invalid")
                assert not result, f"'{domain}' should be invalid but got {result}"
            
            # Test normalization
            assert DomainValidator.normalize_domain("EXAMPLE.COM") == "example.com"
            assert DomainValidator.normalize_domain("http://example.com") == "example.com"
            
            # Test subdomain checking
            assert DomainValidator.is_subdomain("sub.example.com", "example.com")
            assert DomainValidator.is_subdomain("example.com", "example.com")
            assert not DomainValidator.is_subdomain("other.com", "example.com")
            
            print("✅ Domain validation tests passed")
            self.passed += 1
            
        except Exception as e:
            print(f"❌ Domain validation tests failed: {e}")
            import traceback
            traceback.print_exc()
            self.failed += 1
            self.errors.append(f"Domain validation: {e}")
    
    def test_tool_validation(self):
        """Test tool validation system"""
        print("🔍 Testing Tool Validation...")
        
        try:
            # Check all tools
            results = ToolValidator.check_all_tools()
            assert isinstance(results, dict), "Results should be a dictionary"
            assert len(results) > 0, "Should check some tools"
            
            # Each result should have required fields
            for tool_name, info in results.items():
                assert 'available' in info, f"{tool_name} should have 'available' field"
                assert 'description' in info, f"{tool_name} should have 'description' field"
                assert isinstance(info['available'], bool), f"{tool_name} availability should be boolean"
            
            # Test individual tool checking
            nmap_result = ToolValidator.check_tool('nmap')
            assert 'available' in nmap_result, "Nmap check should have availability info"
            
            # Test missing tools list
            missing = ToolValidator.get_missing_tools()
            assert isinstance(missing, list), "Missing tools should be a list"
            
            print("✅ Tool validation tests passed")
            self.passed += 1
            
        except Exception as e:
            print(f"❌ Tool validation tests failed: {e}")
            self.failed += 1
            self.errors.append(f"Tool validation: {e}")
    
    def test_source_manager(self):
        """Test subdomain discovery source management"""
        print("🔍 Testing Source Manager...")
        
        try:
            # Create source manager
            manager = SourceManager()
            
            # Register passive sources
            passive_sources = get_passive_sources()
            for source in passive_sources:
                manager.register_source(source)
            
            assert len(manager.sources) > 0, "Should have registered sources"
            
            # Test source stats
            stats = manager.get_source_stats()
            assert isinstance(stats, dict), "Stats should be a dictionary"
            
            for source_name, source_stats in stats.items():
                assert 'name' in source_stats, f"{source_name} should have name"
                assert 'status' in source_stats, f"{source_name} should have status"
                assert 'enabled' in source_stats, f"{source_name} should have enabled flag"
            
            # Test summary
            summary = manager.get_summary()
            assert 'total_sources' in summary, "Summary should have total sources"
            assert 'enabled_sources' in summary, "Summary should have enabled sources count"
            
            print("✅ Source manager tests passed")
            self.passed += 1
            
        except Exception as e:
            print(f"❌ Source manager tests failed: {e}")
            self.failed += 1
            self.errors.append(f"Source manager: {e}")
    
    def test_scanner_manager(self):
        """Test vulnerability scanner management"""
        print("🔍 Testing Scanner Manager...")
        
        try:
            # Create scanner manager
            manager = ScannerManager()
            
            # Test manual scanner registration
            class TestScanner:
                def __init__(self):
                    self.name = "test_scanner"
                    self.description = "Test scanner"
                    self.enabled = True
                    self.results = []
                    self.errors = []
                
                def get_stats(self):
                    return {
                        'name': self.name,
                        'status': 'ready',
                        'results_count': len(self.results),
                        'errors_count': len(self.errors),
                        'enabled': self.enabled,
                        'description': self.description
                    }
            
            test_scanner = TestScanner()
            manager.register_scanner(test_scanner)
            
            assert len(manager.scanners) == 1, "Should have one registered scanner"
            assert 'test_scanner' in manager.scanners, "Should have test scanner"
            
            # Test scanner stats
            stats = manager.get_scanner_stats()
            assert 'test_scanner' in stats, "Stats should include test scanner"
            
            # Test summary
            summary = manager.get_summary()
            assert 'total_scanners' in summary, "Summary should have total scanners"
            
            print("✅ Scanner manager tests passed")
            self.passed += 1
            
        except Exception as e:
            print(f"❌ Scanner manager tests failed: {e}")
            self.failed += 1
            self.errors.append(f"Scanner manager: {e}")
    
    def test_pentest_manager(self):
        """Test penetration testing module management"""
        print("🔍 Testing Pentest Manager...")
        
        try:
            # Create pentest manager
            manager = PentestManager()
            
            # Test manual module registration
            class TestModule:
                def __init__(self):
                    self.name = "test_module"
                    self.description = "Test pentest module"
                    self.enabled = True
                    self.results = []
                    self.errors = []
                
                def get_stats(self):
                    return {
                        'name': self.name,
                        'status': 'ready',
                        'total_tests': len(self.results),
                        'successful_tests': 0,
                        'errors_count': len(self.errors),
                        'enabled': self.enabled,
                        'description': self.description
                    }
            
            test_module = TestModule()
            manager.register_module(test_module)
            
            assert len(manager.modules) == 1, "Should have one registered module"
            assert 'test_module' in manager.modules, "Should have test module"
            
            # Test module stats
            stats = manager.get_module_stats()
            assert 'test_module' in stats, "Stats should include test module"
            
            # Test summary
            summary = manager.get_summary()
            assert 'total_modules' in summary, "Summary should have total modules"
            
            print("✅ Pentest manager tests passed")
            self.passed += 1
            
        except Exception as e:
            print(f"❌ Pentest manager tests failed: {e}")
            self.failed += 1
            self.errors.append(f"Pentest manager: {e}")
    
    def test_data_models(self):
        """Test data model creation and validation"""
        print("🔍 Testing Data Models...")
        
        try:
            # Test SubdomainResult
            subdomain_result = SubdomainResult(
                subdomain="www.example.com",
                source="test_source",
                ip_address="1.2.3.4",
                confidence=0.9
            )
            
            assert subdomain_result.subdomain == "www.example.com"
            assert subdomain_result.source == "test_source"
            assert subdomain_result.confidence == 0.9
            
            # Test VulnerabilityResult
            vuln_result = VulnerabilityResult(
                title="Test Vulnerability",
                severity=VulnerabilitySeverity.HIGH,
                vulnerability_type="Test Type",
                target="example.com",
                description="Test description"
            )
            
            assert vuln_result.title == "Test Vulnerability"
            assert vuln_result.severity == VulnerabilitySeverity.HIGH
            assert vuln_result.vulnerability_type == "Test Type"
            
            # Test PentestResult
            pentest_result = PentestResult(
                test_type="Test Pentest",
                target="example.com", 
                command="test command",
                success=True,
                output="test output",
                severity=ExploitSeverity.HIGH,
                impact="Test impact",
                recommendations="Test recommendations"
            )
            
            assert pentest_result.test_type == "Test Pentest"
            assert pentest_result.success == True
            assert pentest_result.severity == ExploitSeverity.HIGH
            
            print("✅ Data models tests passed")
            self.passed += 1
            
        except Exception as e:
            print(f"❌ Data models tests failed: {e}")
            self.failed += 1
            self.errors.append(f"Data models: {e}")
    
    async def test_async_operations(self):
        """Test asynchronous operations"""
        print("🔍 Testing Async Operations...")
        
        try:
            # Test NetworkHelper async DNS resolution
            from utils.helpers import NetworkHelper
            
            # Test with a known domain
            result = await NetworkHelper.resolve_domain("google.com")
            assert 'domain' in result, "Result should have domain field"
            assert result['domain'] == "google.com", "Domain should match"
            assert 'ipv4' in result, "Result should have IPv4 field"
            
            # Test invalid domain handling
            invalid_result = await NetworkHelper.resolve_domain("nonexistent.invalid.tld")
            assert 'domain' in invalid_result, "Invalid result should still have domain field"
            
            print("✅ Async operations tests passed")
            self.passed += 1
            
        except Exception as e:
            print(f"❌ Async operations tests failed: {e}")
            self.failed += 1
            self.errors.append(f"Async operations: {e}")
    
    def test_configuration(self):
        """Test configuration management"""
        print("🔍 Testing Configuration...")
        
        try:
            from utils.helpers import ConfigManager
            
            # Test config loading with non-existent file
            config = ConfigManager.load_config("nonexistent.json")
            assert isinstance(config, dict), "Should return empty dict for missing file"
            assert len(config) == 0, "Should be empty for missing file"
            
            # Test config saving and loading
            test_config = {
                "test_key": "test_value",
                "nested": {
                    "key": "value"
                },
                "list": [1, 2, 3]
            }
            
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
                config_path = tmp.name
            
            # Save config
            success = ConfigManager.save_config(test_config, config_path)
            assert success, "Config save should succeed"
            
            # Load config
            loaded_config = ConfigManager.load_config(config_path)
            assert loaded_config == test_config, "Loaded config should match saved config"
            
            # Cleanup
            os.unlink(config_path)
            
            print("✅ Configuration tests passed")
            self.passed += 1
            
        except Exception as e:
            print(f"❌ Configuration tests failed: {e}")
            self.failed += 1
            self.errors.append(f"Configuration: {e}")
    
    async def run_all_tests(self):
        """Run all test suites"""
        print("🚀 Starting ReconForge Integration Tests")
        print("=" * 50)
        
        # Run synchronous tests
        self.test_database()
        self.test_domain_validation()
        self.test_tool_validation()
        self.test_source_manager()
        self.test_scanner_manager()
        self.test_pentest_manager()
        self.test_data_models()
        self.test_configuration()
        
        # Run asynchronous tests
        await self.test_async_operations()
        
        # Print results
        print("\n" + "=" * 50)
        print("🏁 Test Results Summary")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"📊 Total: {self.passed + self.failed}")
        
        if self.errors:
            print("\n🔍 Error Details:")
            for error in self.errors:
                print(f"  • {error}")
        
        if self.failed == 0:
            print("\n🎉 All tests passed! ReconForge is ready to use.")
            return True
        else:
            print(f"\n⚠️  {self.failed} test(s) failed. Please review the errors above.")
            return False


async def main():
    """Main test runner"""
    test_suite = ReconForgeTestSuite()
    success = await test_suite.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())