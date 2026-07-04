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


async def test_scanner_scan_execution():
    """Test the Scanner.scan flow with mocked requests and network calls"""
    from unittest.mock import MagicMock, AsyncMock, patch
    from hacktheweb.core.config import Config
    from hacktheweb.core.ai_engine import AIEngine
    from hacktheweb.core.scanner import Scanner

    print("=" * 60)
    print("Testing Scanner Scan Execution Flow")
    print("=" * 60)

    config = Config()
    config.set('scanning.techniques', ['security_headers', 'xss'])
    config.set('scanning.techniques_explicit', True)

    from hacktheweb.utils import EnterpriseLogger
    EnterpriseLogger.setup(config)

    ai_engine = AIEngine(config)
    scanner = Scanner(config, ai_engine)

    # Mock session
    mock_session = MagicMock()
    
    mock_response = MagicMock()
    mock_resp_obj = AsyncMock()
    mock_resp_obj.status = 200
    mock_resp_obj.headers = {'Server': 'nginx', 'Content-Type': 'text/html'}
    
    # Setup mock cookies to test cookie fingerprinting
    from http.cookies import SimpleCookie
    cookie_obj = SimpleCookie()
    cookie_obj['PHPSESSID'] = 'php-sess-id-value'
    mock_resp_obj.cookies = cookie_obj
    
    # Setup mock HTML containing React elements to test DOM fingerprinting
    mock_resp_obj.text.return_value = '<html><body><div data-reactroot="">React App</div><form action="/login"><input name="username" type="text"/></form></body></html>'
    
    mock_response.__aenter__.return_value = mock_resp_obj
    mock_session.get.return_value = mock_response
    scanner.session = mock_session

    # Mock DNS and Socket calls in ReconEngine to avoid actual network traffic
    with patch('dns.resolver.Resolver.resolve') as mock_dns, \
         patch('socket.gethostbyname') as mock_gethostbyname, \
         patch('socket.create_connection') as mock_create_connection:
        
        mock_dns.side_effect = Exception("DNS Mock Error")
        mock_gethostbyname.return_value = '127.0.0.1'
        mock_create_connection.side_effect = Exception("Socket Mock Error")

        # Run the reconnaissance phase
        recon_data = await scanner._reconnaissance_phase('http://example.com')
        assert recon_data['status_code'] == 200
        assert len(recon_data['forms']) == 1

        analysis = ai_engine.analyze_target(recon_data)
        
        # Verify technology signatures resolved dynamically
        detected_names = [t['name'].lower() for t in analysis['technology_stack']]
        assert 'nginx' in detected_names       # From Server header
        assert 'php' in detected_names         # From PHPSESSID cookie
        assert 'react' in detected_names       # From HTML content pattern
        
        assert len(analysis['priority_vulnerabilities']) > 0

        # Mock scan responses
        mock_scan_resp_wrapper = MagicMock()
        mock_scan_resp_obj = AsyncMock()
        mock_scan_resp_obj.status = 200
        mock_scan_resp_obj.headers = {}
        mock_scan_resp_obj.text.return_value = 'no vulnerability here'
        mock_scan_resp_wrapper.__aenter__.return_value = mock_scan_resp_obj
        
        mock_session.get.return_value = mock_scan_resp_wrapper
        mock_session.post.return_value = mock_scan_resp_wrapper

        # Run the scanning phase
        vulns = await scanner._scanning_phase('http://example.com', analysis)
        assert len(vulns) > 0
        assert any(v['type'] == 'security_headers' for v in vulns)
        
        print("✅ Scanner execution flow tested successfully with mocked session")
        print()
        return True


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    success1 = loop.run_until_complete(test_scanner_integration())
    success2 = loop.run_until_complete(test_scanner_scan_execution())
    sys.exit(0 if (success1 and success2) else 1)
