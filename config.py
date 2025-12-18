"""
Configuration module for environment variables
"""
import os

def load_config():
    """Load configuration from .env file"""
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

# Load config when module is imported
load_config()

# Export config values
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
