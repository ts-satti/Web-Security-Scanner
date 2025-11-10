## Purpose
Short, actionable guidance for AI coding agents working on the Security Scanner Flask app.

## High-level architecture (what to know quickly)
- App entry: `run.py` instantiates the Flask app via `create_app()` in `app.py`.
- `app.py` contains the application factory, user auth routes, and the background runner `run_security_scan` plus the global `running_scans` dict that controls stop flags.
- Routes are implemented either directly in `app.py` or provided by `main_routes.py` (a `Blueprint` named `main`). Key endpoints:
  - POST `/scan` : start a scan (form fields: `target_url`, `scan_type`) — returns `{'scan_id': <id>}`
  - GET `/scan-progress/<id>` : returns progress object from `utils/helpers.py::progress_manager`
  - POST `/stop-scan/<id>` : sets `running_scans[scan_id]['stop_flag'] = True`
  - GET `/results/<id>` and `/export-pdf/<id>` for results and PDF export (PDFs use `reportlab`).

## Scanner subsystem
- Scanners live under `scanners/` and are created via `scanners/scanner_factory.py`.
- Add a scanner by creating a class that subclasses `scanners/base_scanner.SecurityScanner` and implement `run_scan()`; then register the key in `ScannerFactory.create_scanner` mapping.
- Scanners should use `progress_manager.update(...)` and `progress_manager.add_activity_log(...)` (from `utils/helpers.py`) for reporting progress and logs.
- Scanners should check stop conditions via the `running_scans` global (see `SecurityScanner.check_stop_flag()` implementation).

## Progress & activity contract (important for UI)
- The progress object returned by `/scan-progress/<id>` is managed by `utils/helpers.py::ProgressManager` and contains keys:
  - `progress` (0-100), `status` (running/completed/stopped/error), `current_task`, `vulnerabilities_found`, `security_score`, `activity_log` (list of {timestamp,message,type}).
- When updating progress from scanners use:
  - `progress_manager.update(scan_id, progress, status, current_task, vulnerabilities, security_score, detailed_message)`
  - `progress_manager.add_activity_log(scan_id, message, log_type)`
- Frontend file to keep in sync: `static/js/main.js` — it polls `/scan-progress/<id>` and expects the contract above. If you change the JSON shape, update this file.

## Conventions & gotchas
- Circular-imports are avoided by importing scanners inside `create_app()` in `app.py`. Be careful when importing `app` symbols from other modules — some modules import `run_security_scan` and `running_scans` from `app.py`.
- Background scanning runs in threads (see `threading.Thread(..., target=run_security_scan, ...)`) and uses `app.app_context()` internally — keep thread-safe code (use `progress_manager` which is thread-safe).
- Persisted models: `models.py` (SQLAlchemy) — new scanner results should surface through `Scan.get_results()` used by `/results/<id>` and PDF export.
- PDF generation uses `reportlab` in `app.py`/`main_routes.py` — heavy CPU work; ensure exceptions are handled and streamed via `BytesIO`.

## How to run & debug locally (Windows PowerShell examples)
1. Install dependencies: `pip install -r requirements.txt`
2. Run the app (development):
```powershell
$Env:FLASK_ENV = 'development'; python .\run.py
```
Or simply:
```powershell
python .\run.py
```
Open http://localhost:5000

## Adding a new scanner — practical checklist
1. Create a new scanner file under `scanners/standard/` or `scanners/deep/` and subclass `SecurityScanner` from `scanners/base_scanner.py`.
2. Implement `run_scan()` and use `self.update_progress(...)` and `self.log_activity(...)` (or call `progress_manager` directly).
3. Add the scanner class to `scanners/scanner_factory.py` mapping with a clear `scan_type` key.
4. Ensure any long CPU-bound work does not block the Flask main thread (scan runs on background thread already).
5. Add a small entry or unit test (if you add tests) that exercises `run_scan()` with mocked HTTP responses.

## Quick references (files to inspect)
- `app.py` — factory, auth, scan orchestration, `run_security_scan`, `running_scans` global
- `main_routes.py` — blueprint alternative for routes; duplicates route logic, watch for subtle differences
- `scanners/` — scanner implementations and `scanner_factory.py`
- `scanners/base_scanner.py` — SecurityScanner base class, logging and detection helpers
- `utils/helpers.py` — `ProgressManager` (thread-safe) used by UI
- `static/js/main.js` — frontend polling and UI expectations
- `requirements.txt` — pinned dependencies (Flask, requests, beautifulsoup4, reportlab, etc.)

## When to ask the human
- If a change touches the JSON contract returned by `/scan-progress/<id>` (frontend/back-end must both be updated).
- If adding a scanner that needs external system access (e.g., port scanning with root privileges, external APIs) — ask for environment/CI adjustments.
- If you need database migration steps — consult `config.py` and `models.py` before making schema changes.

Please review this draft and tell me if you'd like more detail on any area (DB setup, test harness, or examples of adding a specific scanner). I can iterate the file.