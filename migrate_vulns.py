from app import create_app
from models import db, Scan, Vulnerability

app = create_app()
with app.app_context():
    # First, clear existing vulnerabilities to avoid duplicates on re-run
    Vulnerability.query.delete()
    db.session.commit()
    
    scans = Scan.query.all()
    count = 0
    for scan in scans:
        results = scan.get_results()
        vulns = results.get('vulnerabilities', [])
        for v in vulns:
            # Always create vulnerability record (no duplicate check)
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
            count += 1
    db.session.commit()
    print(f"Migrated {count} vulnerabilities from Scan.results to Vulnerability table.")