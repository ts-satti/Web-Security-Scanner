import pytest
from scanners.deep.enhanced_xss_scanner import EnhancedXSSScanner


def test_validate_target_url_good():
    s = EnhancedXSSScanner('http://example.com', 'scan1')
    assert s._validate_target_url() is True


def test_validate_target_url_https():
    s = EnhancedXSSScanner('https://example.com', 'scan1')
    assert s._validate_target_url() is True


def test_validate_target_url_bad_scheme():
    s = EnhancedXSSScanner('ftp://example.com', 'scan1')
    assert s._validate_target_url() is False


def test_validate_target_url_missing_host():
    s = EnhancedXSSScanner('http://', 'scan1')
    assert s._validate_target_url() is False


def test_validate_target_url_invalid_chars():
    s = EnhancedXSSScanner('http://example.com<bad>', 'scan1')
    assert s._validate_target_url() is False


def test_build_dom_test_url_fragment():
    s = EnhancedXSSScanner('http://example.com/page', 'scan1')
    payload = "#<img src=x onerror=alert(1)>"
    url = s._build_dom_test_url(payload)
    assert url == 'http://example.com/page' + payload


def test_build_dom_test_url_encoded_param_no_query():
    s = EnhancedXSSScanner('http://example.com/page', 'scan1')
    payload = "<script>alert(1)</script>"
    url = s._build_dom_test_url(payload)
    assert 'xss_payload=' in url
    # payload should be percent-encoded (case-insensitive check)
    assert '%3cscript%3e' in url.lower()


def test_build_dom_test_url_encoded_param_with_query():
    s = EnhancedXSSScanner('http://example.com/page?foo=bar', 'scan1')
    payload = "<img src=x onerror=alert(1)>"
    url = s._build_dom_test_url(payload)
    assert url.startswith('http://example.com/page?')
    assert '&xss_payload=' in url
