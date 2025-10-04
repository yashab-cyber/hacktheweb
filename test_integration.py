#!/usr/bin/env python3
"""
Quick test to verify all scanners are integrated
"""

import sys
import asyncio

async def test_scanner_integration():
    """Test that all scanners can be imported and initialized"""
    
    print("=" * 60)
    print("HackTheWeb Scanner Integration Test")
    print("=" * 60)
    print()
    
    try:
        # Test imports
        print("[1/3] Testing scanner imports...")
        from hacktheweb.scanners import (
            XSSScanner,
            SQLiScanner,
            CSRFScanner,
            SSRFScanner,
            LFIScanner,
            SecurityHeadersScanner,
            XXEScanner,
            RCEScanner,
            IDORScanner,
            OpenRedirectScanner,
            CORSScanner,
            PathTraversalScanner,
            NoSQLiScanner,
            LDAPIScanner,
            SSTIScanner,
        )
        print("✅ All scanners imported successfully")
        print()
        
        # Test configuration
        print("[2/3] Testing configuration...")
        from hacktheweb.core.config import Config
        config = Config()
        print("✅ Configuration loaded successfully")
        print()
        
        # Test scanner initialization
        print("[3/3] Testing scanner initialization...")
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            scanners = {
                'XSS': XSSScanner(config, session),
                'SQLi': SQLiScanner(config, session),
                'CSRF': CSRFScanner(config, session),
                'SSRF': SSRFScanner(config, session),
                'LFI': LFIScanner(config, session),
                'Security Headers': SecurityHeadersScanner(config, session),
                'XXE': XXEScanner(config, session),
                'RCE': RCEScanner(config, session),
                'IDOR': IDORScanner(config, session),
                'Open Redirect': OpenRedirectScanner(config, session),
                'CORS': CORSScanner(config, session),
                'Path Traversal': PathTraversalScanner(config, session),
                'NoSQLi': NoSQLiScanner(config, session),
                'LDAPi': LDAPIScanner(config, session),
                'SSTI': SSTIScanner(config, session),
            }
            
            print("✅ All scanners initialized successfully")
            print()
            
            # Display scanner summary
            print("=" * 60)
            print("Scanner Summary")
            print("=" * 60)
            for name, scanner in scanners.items():
                print(f"  ✅ {name:20s} - {scanner.__class__.__name__}")
            
            print()
            print("=" * 60)
            print(f"Total Active Scanners: {len(scanners)}")
            print("=" * 60)
            print()
            print("🎉 All integration tests passed!")
            print()
            
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_scanner_integration())
    sys.exit(0 if success else 1)
