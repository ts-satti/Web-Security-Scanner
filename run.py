#!/usr/bin/env python3
"""
Security Scanner - Main Application Entry Point
"""
import os
from app import create_app

# Set environment
env = os.environ.get('FLASK_ENV', 'development')
app = create_app(env)

if __name__ == '__main__':
    print(f"🚀 Starting Security Scanner in {env} mode...")
    print(f"📍 Access the application at: http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=(env == 'development'))