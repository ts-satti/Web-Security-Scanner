from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def get_recent_scans(self, limit=10):
        """Get recent scans for user"""
        return self.scans.order_by(Scan.created_at.desc()).limit(limit).all()
    
    def __repr__(self):
        return f'<User {self.email}>'

class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)
    results = db.Column(db.Text)  # JSON stored as text
    vulnerabilities_count = db.Column(db.Integer, default=0)
    security_score = db.Column(db.Integer, default=100)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_results(self, results_dict):
        """Safely set results as JSON string"""
        try:
            self.results = json.dumps(results_dict, default=str)
        except (TypeError, ValueError) as e:
            self.results = json.dumps({'error': f'Failed to serialize results: {str(e)}'})
    
    def get_results(self):
        """Safely get results as dictionary"""
        if not self.results:
            return {}
        try:
            return json.loads(self.results)
        except (json.JSONDecodeError, TypeError):
            return {'error': 'Invalid results format'}
    
    def update_stats(self):
        """Update vulnerability count and security score from results"""
        results = self.get_results()
        vulnerabilities = results.get('vulnerabilities', [])
        self.vulnerabilities_count = len(vulnerabilities)
        self.security_score = max(0, 100 - (self.vulnerabilities_count * 10))
    
    def get_high_risk_count(self):
        """Get count of only High risk vulnerabilities"""
        results = self.get_results()
        vulnerabilities = results.get('vulnerabilities', [])
        high_count = 0
        
        for vuln in vulnerabilities:
            if vuln.get('risk_level') == 'High':
                high_count += 1
                
        return high_count
    
    def validate_results_integrity(self):
        """Validate that results data is consistent - UPDATED: Removed Critical"""
        results = self.get_results()
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Count by risk level (REMOVED Critical)
        risk_counts = {
            'High': 0, 
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in vulnerabilities:
            risk_level = vuln.get('risk_level', 'Info')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        # Verify counts match
        total_from_risk = sum(risk_counts.values())
        if total_from_risk != self.vulnerabilities_count:
            print(f"⚠️ Count mismatch: DB={self.vulnerabilities_count}, Calculated={total_from_risk}")
            return False
        
        return risk_counts
    
    def __repr__(self):
        return f'<Scan {self.id} - {self.target_url}>'

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False, index=True)
    risk_level = db.Column(db.String(20), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(500))
    payload = db.Column(db.Text)
    evidence = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    cwe_id = db.Column(db.String(20))
    cvss_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'category': self.category,
            'risk_level': self.risk_level,
            'title': self.title,
            'description': self.description,
            'location': self.location,
            'payload': self.payload,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score
        }
    
    def __repr__(self):
        return f'<Vulnerability {self.id} - {self.category}>'