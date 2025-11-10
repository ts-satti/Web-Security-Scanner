import os
from datetime import timedelta

class Config:
    """Application configuration"""
    
    # Security - CHANGE THIS IN PRODUCTION!
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database
    basedir = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 
        f'sqlite:///{os.path.join(basedir, "instance", "security_scanner.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Scanner Configuration
    MAX_WORKERS = int(os.environ.get('MAX_WORKERS', 3))
    REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 10))
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', 300))
    REQUEST_DELAY = float(os.environ.get('REQUEST_DELAY', 0.5))
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # Application
    UPLOAD_FOLDER = os.path.join(basedir, 'instance', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    @classmethod
    def init_app(cls, app):
        """Initialize application with configuration"""
        # Create instance directory if it doesn't exist
        instance_path = os.path.join(cls.basedir, 'instance')
        os.makedirs(instance_path, exist_ok=True)
        os.makedirs(cls.UPLOAD_FOLDER, exist_ok=True)

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Override secret key for production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    @classmethod
    def init_app(cls, app):
        super().init_app(app)
        # Validate production settings
        if not cls.SECRET_KEY or cls.SECRET_KEY == 'dev-secret-key-change-in-production':
            raise ValueError("SECRET_KEY must be set in production environment")

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}