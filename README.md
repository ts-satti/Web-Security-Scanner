Web Security Scanner

A small Flask-based security scanner used for demos and testing.

Quick dev setup (PowerShell on Windows):

1. Create a virtual environment and activate it:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the app:

```powershell
python run.py
```

Testing
-------

This project uses pytest for unit tests. Add `pytest` to your environment if it's not installed. To install pytest and run tests in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install pytest
pytest -q
```

Or run a single test file:

```powershell
pytest -q tests/test_enhanced_xss_scanner.py
```

Optional: Playwright-based DOM checks
-----------------------------------

For higher-fidelity DOM XSS detection you can enable a headless browser check using Playwright. This is optional and must be explicitly enabled in scanner config to avoid the extra dependency and browser download.

Install Playwright and the Chromium browser:

```powershell
pip install playwright
playwright install chromium
```

Enable Playwright in scan config, for example when creating a scan request set:

{
	"target_url": "http://example.com",
	"scan_type": "deep",
	"config": { "enable_browser_dom_checks": true }
}

When enabled, the scanner will attempt a headless browser run for DOM vectors and log any alerts or reflections it observes. If Playwright is not installed, the scanner falls back to the existing server-side checks.

Notes
-----
- Tests exercise scanner helpers and are safe to run against local code. They do not execute malicious payloads against external targets.
- For integration scans (scanning remote hosts) ensure you have permission to test the target.
