# app.py
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
from flask_login import LoginManager, login_required, current_user
from datetime import datetime
from zoneinfo import ZoneInfo
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import threading
from flask_migrate import Migrate

from config import config
from models import db, User, Scan, Vulnerability
from utils.security import SecurityUtils
from utils.validators import InputValidators
from utils.helpers import progress_manager

# Import auth functions and login manager
from auth import login_route, register_route, logout_route, login_manager

# Global dictionaries to track running scans
running_scans = {}


def create_app(environment='development'):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[environment])
    config[environment].init_app(app)
    
    # Initialize extensions
    db.init_app(app)
    # Initialize Flask-Migrate
    migrate = Migrate(app, db)
    
    # Setup login manager
    login_manager.init_app(app)
    
    # Register authentication routes directly (no blueprint)
    app.route('/login', methods=['GET', 'POST'])(login_route)
    app.route('/register', methods=['GET', 'POST'])(register_route)
    app.route('/logout')(logout_route)
    
    # Import scanners here to avoid circular imports
    with app.app_context():
        from scanners.scanner_factory import ScannerFactory
    
    # Routes - Only non-authentication routes remain
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        # Get ALL scans for accurate statistics calculation
        all_scans = Scan.query.filter(Scan.user_id == current_user.id, Scan.status != 'discarded').all()
        
        # Calculate statistics from ALL scans
        total_scans = len(all_scans)
        completed_scans = [s for s in all_scans if s.status == 'completed']
        active_scans = [s for s in all_scans if s.status == 'running']
        total_vulnerabilities = sum(s.vulnerabilities_count or 0 for s in all_scans)
        
        # Calculate vulnerabilities by severity
        vuln_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0,
            'Other': 0
        }

        for scan in all_scans:
            if scan.status == 'completed' and scan.results:
                results = scan.get_results()
                vulnerabilities = results.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    risk_level = vuln.get('risk_level', 'Other')
                    if risk_level in vuln_counts:
                        vuln_counts[risk_level] += 1
                    else:
                        vuln_counts['Other'] += 1
                     
        
        # Calculate success rate
        success_rate = round((len(completed_scans) / total_scans * 100)) if total_scans > 0 else 0
        
        # Calculate average vulnerabilities per scan
        avg_vulns = round(total_vulnerabilities / len(completed_scans), 1) if len(completed_scans) > 0 else 0
        
        stats = {
            'total_scans': total_scans,
            'completed_scans': len(completed_scans),
            'active_scans': len(active_scans),
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': vuln_counts['Critical'],
            'high_vulnerabilities': vuln_counts['High'],
            'medium_vulnerabilities': vuln_counts['Medium'],
            'low_vulnerabilities': vuln_counts['Low'],
            'info_vulnerabilities': vuln_counts['Info'],
            'other_vulnerabilities': vuln_counts['Other'],
            'success_rate': success_rate,
            'avg_vulnerabilities': avg_vulns
        }
        
        # Get all scans ordered by most recent first (no limit for scrollable table)
        recent_scans = Scan.query.filter(Scan.user_id == current_user.id, Scan.status != 'discarded').order_by(Scan.created_at.desc()).all()
        
        return render_template('dashboard.html', scans=recent_scans, stats=stats)

    @app.route('/scans')
    def scans_page():
        return render_template('scans.html')

    @app.route('/profile')
    @login_required
    def profile():
        return render_template('profile.html')  

    @app.route('/dashboard-charts-data')
    @login_required
    def dashboard_charts_data():
        """Return data for dashboard charts: vulnerabilities by type and by severity."""
        user_scan_ids = [s.id for s in Scan.query.filter(Scan.user_id == current_user.id, Scan.status != 'discarded').all()]
        if not user_scan_ids:
            return jsonify({
                'by_type': {},
                'by_severity': {}
            })
        from models import Vulnerability
        vulns = Vulnerability.query.filter(Vulnerability.scan_id.in_(user_scan_ids)).all()
        by_type = {}
        for v in vulns:
            by_type[v.category] = by_type.get(v.category, 0) + 1
        by_severity = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Other': 0}
        for v in vulns:
            level = v.risk_level if v.risk_level in by_severity else 'Other'
            by_severity[level] += 1
        return jsonify({
            'by_type': by_type,
            'by_severity': by_severity
        })

    @app.route('/recent-scans')
    @login_required
    def recent_scans():
        """Return recent scans as JSON for AJAX refresh (used when navigating back)."""
        scans = Scan.query.filter(Scan.user_id == current_user.id, Scan.status != 'discarded').order_by(Scan.created_at.desc()).limit(100).all()
        scans_data = [
            {
                'id': s.id,
                'target_url': s.target_url,
                'scan_type': s.scan_type.replace('_', ' ').title(),
                'status': s.status,
                'vulnerabilities_count': s.vulnerabilities_count,
                'security_score': s.security_score,
                # Return ISO8601 UTC timestamp so clients can render in local timezone
                'created_at': (s.created_at.replace(microsecond=0).isoformat() + 'Z')
            }
            for s in scans
        ]
        return jsonify({'scans': scans_data})


    @app.route('/dashboard-stats')
    @login_required
    def dashboard_stats():
        """Return aggregated statistics for the logged-in user's dashboard.

        This endpoint intentionally does not limit results so it returns accurate
        totals even when the user has more than 100 scans.
        """
        scans = Scan.query.filter(Scan.user_id == current_user.id, Scan.status != 'discarded').all()

        total_scans = len(scans)
        completed_scans = sum(1 for s in scans if s.status == 'completed')
        active_scans = sum(1 for s in scans if s.status == 'running')
        total_vulnerabilities = sum((s.vulnerabilities_count or 0) for s in scans)

        # Calculate vulnerabilities by severity
        vuln_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0,
            'Other': 0
        }

        for scan in scans:
            if scan.status == 'completed' and scan.results:
                results = scan.get_results()
                vulnerabilities = results.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    risk_level = vuln.get('risk_level', 'Other')
                    if risk_level in vuln_counts:
                        vuln_counts[risk_level] += 1
                    else:
                        vuln_counts['Other'] += 1

        success_rate = round((completed_scans / total_scans * 100)) if total_scans > 0 else 0
        avg_vulns = round((total_vulnerabilities / completed_scans), 1) if completed_scans > 0 else 0

        return jsonify({
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'active_scans': active_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': vuln_counts['Critical'],
            'high_vulnerabilities': vuln_counts['High'],
            'medium_vulnerabilities': vuln_counts['Medium'],
            'low_vulnerabilities': vuln_counts['Low'],
            'info_vulnerabilities': vuln_counts['Info'],
            'other_vulnerabilities': vuln_counts['Other'],
            'success_rate': success_rate,
            'avg_vulnerabilities': avg_vulns
        })
    
    @app.route('/scan', methods=['POST'])
    @login_required
    def start_scan():
        target_url = request.form.get('target_url', '').strip()
        scan_type = request.form.get('scan_type', '')
        
        # Validate inputs
        if not target_url:
            return jsonify({'error': 'Please enter a target URL'}), 400
        
        if not scan_type:
            return jsonify({'error': 'Please select a scan type'}), 400
        
        # Validate URL
        is_valid, sanitized_url, error_msg = SecurityUtils.validate_url(target_url)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Validate scan type
        is_valid, scan_msg = InputValidators.validate_scan_type(scan_type)
        if not is_valid:
            return jsonify({'error': scan_msg}), 400
        
        # Create scan record
        scan = Scan(
            user_id=current_user.id,
            target_url=sanitized_url,
            scan_type=scan_type,
            status='running',
            started_at=datetime.utcnow()
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Initialize progress tracking
        progress_manager.update(scan.id, 0, 'initializing', 'Starting scan...')
        
        # Initialize running scans tracking
        running_scans[scan.id] = {
            'stop_flag': False,
            'paused': False,
            'scanner': None
        }
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_security_scan,
            args=(app, scan.id, sanitized_url, scan_type)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan.id,
            'status': 'started',
            'message': 'Scan started successfully',
            'target_url': sanitized_url
        })
    @app.route('/scan-progress/<int:scan_id>')
    @login_required
    def get_scan_progress(scan_id):
        scan = Scan.query.get_or_404(scan_id)
        
        # Authorization check
        if scan.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        progress_data = progress_manager.get(scan_id)
        # Prioritize scan.status from database (set during pause/resume)
        # But also check running_scans for real-time pause state
        if scan_id in running_scans and running_scans[scan_id].get('paused', False):
            progress_data['status'] = 'paused'
        else:
            progress_data['status'] = scan.status
        
        return jsonify(progress_data)
    
    @app.route('/stop-scan/<int:scan_id>', methods=['POST'])
    @login_required
    def stop_scan(scan_id):
        scan = Scan.query.get_or_404(scan_id)
        
        # Authorization check
        if scan.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        if scan_id in running_scans:
            # Toggle pause/resume functionality
            if running_scans[scan_id]['paused']:
                # Resume the scan
                running_scans[scan_id]['paused'] = False
                scan.status = 'running'
                db.session.commit()
                
                progress_data = progress_manager.get(scan_id)
                progress_manager.update(
                    scan_id, 
                    progress_data.get('progress', 0), 
                    'running', 
                    progress_data.get('current_task', 'Resuming scan...')
                )
                progress_manager.add_activity_log(scan_id, '▶️ Scan resumed by user', 'info')
                
                return jsonify({'status': 'running', 'message': 'Scan resumed successfully', 'action': 'resume'})
            else:
                # Pause the scan
                running_scans[scan_id]['paused'] = True
                # Update database status to paused
                scan.status = 'paused'
                db.session.commit()
                
                progress_manager.add_activity_log(scan_id, '⏸️ Scan paused by user', 'info')
                
                progress_data = progress_manager.get(scan_id)
                progress_manager.update(
                    scan_id, 
                    progress_data.get('progress', 0), 
                    'paused', 
                    'Scan paused - Click resume to continue'
                )
                
                return jsonify({'status': 'paused', 'message': 'Scan paused successfully', 'action': 'pause'})
        
        return jsonify({'error': 'Scan not running'}), 404

    @app.route('/stop-and-discard/<int:scan_id>', methods=['POST'])
    @login_required
    def stop_and_discard(scan_id):
        """Stop a running scan and remove it from storage/history."""
        scan = Scan.query.get_or_404(scan_id)

        # Authorization check
        if scan.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403

        # If running, set stop flag and attempt to stop scanner
        if scan_id in running_scans:
            running_scans[scan_id]['stop_flag'] = True
            if running_scans[scan_id].get('scanner'):
                try:
                    running_scans[scan_id]['scanner'].stop_scan()
                except Exception:
                    pass

        # Mark the scan as discarded instead of deleting to avoid race conditions with the running thread
        try:
            scan.status = 'discarded'
            scan.completed_at = datetime.utcnow()
            db.session.commit()

            try:
                progress_manager.delete(scan_id)
            except Exception:
                pass

            # Keep running_scans entry so background thread can observe stop flag and exit cleanly.
            return jsonify({'status': 'discarded', 'message': 'Scan stopped and discarded (soft)'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to mark scan as discarded: {str(e)}'}), 500

    @app.route('/delete-scan/<int:scan_id>', methods=['POST'])
    @login_required
    def delete_scan(scan_id):
        scan = Scan.query.get_or_404(scan_id)

        # Authorization check
        if scan.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403

        # If scan is running, attempt to stop it first
        if scan_id in running_scans:
            running_scans[scan_id]['stop_flag'] = True
            if running_scans[scan_id].get('scanner'):
                try:
                    running_scans[scan_id]['scanner'].stop_scan()
                except Exception:
                    pass

        # Delete scan and related vulnerabilities (cascade)
        try:
            db.session.delete(scan)
            db.session.commit()
            # Remove any transient progress data
            try:
                progress_manager.delete(scan_id)
            except Exception:
                pass

            return jsonify({'status': 'deleted', 'message': 'Scan deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete scan: {str(e)}'}), 500
    
    @app.route('/results/<int:scan_id>')
    @login_required
    def results(scan_id):
        scan = Scan.query.get_or_404(scan_id)
        
        # Authorization check
        if scan.user_id != current_user.id:
            flash('Unauthorized access', 'error')
            return redirect(url_for('dashboard'))
        
        results_data = scan.get_results()

        # Normalize risk level casing for consistent display
        vulnerabilities = results_data.get('vulnerabilities', []) if isinstance(results_data, dict) else []
        for vuln in vulnerabilities:
            rl = vuln.get('risk_level', 'Info')
            rl_str = str(rl).strip() if rl is not None else 'Info'
            if rl_str.lower() in ('high', 'medium', 'low', 'info'):
                vuln['risk_level'] = rl_str.capitalize()
            else:
                vuln['risk_level'] = rl_str.title()
        if isinstance(results_data, dict):
            results_data['vulnerabilities'] = vulnerabilities

        scans = Scan.query.filter(Scan.user_id == current_user.id, Scan.status != 'discarded').order_by(Scan.created_at.desc()).limit(10).all()

        completion_dt = scan.completed_at or scan.created_at
        completion_iso = ''
        completion_display = 'N/A'
        if completion_dt:
            if completion_dt.tzinfo is None:
                completion_iso = completion_dt.replace(microsecond=0).isoformat() + 'Z'
            else:
                completion_iso = (
                    completion_dt.astimezone(ZoneInfo('UTC'))
                    .replace(microsecond=0)
                    .isoformat()
                    .replace('+00:00', 'Z')
                )
            completion_display = completion_dt.strftime('%Y-%m-%d at %H:%M')
        
        return render_template(
            'results.html',
            results=results_data,
            scan=scan,
            scans=scans,
            completion_iso=completion_iso,
            completion_display=completion_display
        )
    
    @app.route('/about')
    def about():
        return render_template('about.html')
    
    @app.route('/export-pdf/<int:scan_id>')
    @login_required
    def export_pdf(scan_id):
        """Generate and download PDF report for scan results"""
        scan = Scan.query.get_or_404(scan_id)
        
        # Authorization check
        if scan.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        try:
            # Generate PDF content
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=16,
                spaceAfter=30,
                textColor=colors.HexColor('#2c3e50')
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=12,
                spaceAfter=12,
                textColor=colors.HexColor('#34495e')
            )
            
            # Story to hold PDF content
            story = []
            
            # Title
            story.append(Paragraph("Security Scan Report", title_style))
            story.append(Spacer(1, 20))
            
            # Scan Information
            story.append(Paragraph("Scan Information", heading_style))
            info_data = [
                ['Target URL:', scan.target_url],
                ['Scan Type:', scan.scan_type.replace('_', ' ').title()],
                ['Scan Date:', scan.created_at.strftime('%Y-%m-%d %H:%M:%S')],
                ['Status:', scan.status.title()],
                ['Security Score:', f"{scan.security_score}/100"],
                ['Vulnerabilities Found:', str(scan.vulnerabilities_count)]
            ]
            
            info_table = Table(info_data, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(info_table)
            story.append(Spacer(1, 20))
            
            # Vulnerabilities
            results_data = scan.get_results()
            vulnerabilities = results_data.get('vulnerabilities', [])
            
            if vulnerabilities:
                story.append(Paragraph("Vulnerabilities Found", heading_style))
                
                # Group by category
                categories = {}
                for vuln in vulnerabilities:
                    category = vuln.get('category', 'Other')
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(vuln)
                
                for category, vulns in categories.items():
                    story.append(Paragraph(f"Category: {category}", styles['Heading3']))
                    
                    for i, vuln in enumerate(vulns, 1):
                        # Risk level color
                        risk_level = vuln.get('risk_level', 'Unknown')
                        risk_color = colors.darkred if risk_level == 'Critical' else \
                                    colors.red if risk_level == 'High' else \
                                    colors.orange if risk_level == 'Medium' else \
                                    colors.green if risk_level == 'Low' else \
                                    colors.blue if risk_level == 'Info' else colors.grey
                        
                        # Vulnerability details
                        story.append(Paragraph(f"{i}. {vuln.get('title', 'Unknown')} - <font color='{risk_color.hexval()}'>{risk_level}</font>", styles['Normal']))
                        
                        if vuln.get('location'):
                            story.append(Paragraph(f"Location: {vuln.get('location')}", styles['Normal']))
                        
                        if vuln.get('description'):
                            story.append(Paragraph(f"Description: {vuln.get('description')}", styles['Normal']))
                        
                        if vuln.get('recommendation'):
                            story.append(Paragraph(f"Recommendation: {vuln.get('recommendation')}", styles['Normal']))
                        
                        story.append(Spacer(1, 10))
                    
                    story.append(Spacer(1, 10))
            else:
                story.append(Paragraph("No vulnerabilities found during this scan.", styles['Normal']))
                story.append(Spacer(1, 10))
            
            # Footer
            story.append(Spacer(1, 20))
            story.append(Paragraph("Generated by Security Scanner", styles['Italic']))
            story.append(Paragraph(f"Report generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Italic']))
            
            # Build PDF
            doc.build(story)
            buffer.seek(0)
            
            filename = f"security-scan-report-{scan_id}.pdf"
            
            return send_file(
                buffer,
                as_attachment=True,
                download_name=filename,
                mimetype='application/pdf'
            )
            
        except Exception as e:
            print(f"PDF generation error: {e}")
            flash(f'Error generating PDF: {str(e)}', 'error')
            return redirect(url_for('results', scan_id=scan_id))
    
    # Background scan function
    def run_security_scan(app, scan_id, target_url, scan_type):
        """Run security scan in background thread"""
        with app.app_context():
            try:
                scan = Scan.query.get(scan_id)
                if not scan:
                    print(f"[-] Scan {scan_id} not found")
                    return
                
                print(f"[*] Starting {scan_type} scan for: {target_url}")
                
                # Create scanner instance
                scanner_config = {
                    'REQUEST_TIMEOUT': app.config.get('REQUEST_TIMEOUT', 10),
                    'REQUEST_DELAY': app.config.get('REQUEST_DELAY', 0.5),
                    'MAX_WORKERS': app.config.get('MAX_WORKERS', 3)
                }
                
                scanner = ScannerFactory.create_scanner(scan_type, target_url, scan_id, scanner_config)
                
                # Store scanner reference for stopping
                running_scans[scan_id]['scanner'] = scanner
                
                # Check if scan was stopped before starting
                if running_scans[scan_id]['stop_flag']:
                    scan.status = 'stopped'
                    db.session.commit()
                    return
                
                # Run the scan
                results = scanner.run_scan()
                
                # Before persisting results, re-load scan and check if it was discarded
                refreshed_scan = Scan.query.get(scan_id)
                if not refreshed_scan:
                    print(f"[!] Scan {scan_id} no longer exists in DB; skipping result persistence")
                    return

                # If the scan was marked discarded or a stop_flag was set, skip persisting results.
                try:
                    stop_flag_set = (scan_id in running_scans and running_scans[scan_id].get('stop_flag'))
                except Exception:
                    stop_flag_set = False

                if refreshed_scan.status == 'discarded' or stop_flag_set:
                    print(f"[!] Scan {scan_id} marked discarded or stop flag set; skipping result persistence")
                    try:
                        progress_manager.delete(scan_id)
                    except Exception:
                        pass
                    return

                # Update scan record
                scan.status = results.get('status', 'completed')
                scan.set_results(results)
                scan.update_stats()

                if scan.status == 'completed':
                    scan.completed_at = datetime.utcnow()

                db.session.commit()

                # Automatically save vulnerabilities to Vulnerability table
                if scan.status == 'completed':
                    from models import Vulnerability
                    vulns = results.get('vulnerabilities', [])
                    for v in vulns:
                        vuln = Vulnerability(
                            scan_id=scan.id,
                            category=v.get('category', ''),
                            risk_level=v.get('risk_level', ''),
                            title=v.get('title', ''),
                            description=v.get('description', ''),
                            location=v.get('location', ''),
                            payload=v.get('payload', ''),
                            evidence=v.get('evidence', ''),
                            recommendation=v.get('recommendation', ''),
                            cwe_id=v.get('cwe_id', ''),
                            cvss_score=v.get('cvss_score', 0.0)
                        )
                        db.session.add(vuln)
                    db.session.commit()
                    print(f"[+] Saved {len(vulns)} vulnerabilities to Vulnerability table")

                print(f"[+] Scan {scan_id} completed with status: {scan.status}")
                
            except Exception as e:
                print(f"[-] Scan error: {e}")
                try:
                    scan = Scan.query.get(scan_id)
                    if scan:
                        scan.status = 'error'
                        scan.error_message = str(e)
                        scan.set_results({'error': str(e), 'vulnerabilities': []})
                        db.session.commit()
                except Exception as db_error:
                    print(f"[-] Database error: {db_error}")
            
            finally:
                # Clean up
                if scan_id in running_scans:
                    del running_scans[scan_id]
    
    # Create database tables
    with app.app_context():
        db.create_all()
        print("[+] Database tables created")
    
    return app