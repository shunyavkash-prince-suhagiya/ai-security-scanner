"""
Shared scanner configuration.
"""

PATTERNS = {
    'Email Address': {
        'regex': r'\b[\w\.-]+@[\w\.-]+\.\w{2,}\b',
        'risk': 'MEDIUM',
        'description': 'Email address found in plain text'
    },
    'Hardcoded Password': {
        'regex': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\'\s]{4,})["\']',
        'risk': 'HIGH',
        'description': 'Hardcoded password detected'
    },
    'API Key': {
        'regex': r'(?i)(api[_-]?key|token|secret)\s*[=:]\s*["\']([a-zA-Z0-9_-]{16,})["\']',
        'risk': 'CRITICAL',
        'description': 'API key or token found'
    },
    'Basic Auth URL': {
        'regex': r'https?://([^:]+):([^@]+)@',
        'risk': 'CRITICAL',
        'description': 'Credentials in URL (Basic Auth)'
    },
    'AWS Key': {
        'regex': r'(?i)(AKIA|ASIA)[A-Z0-9]{16}',
        'risk': 'CRITICAL',
        'description': 'AWS Access Key found'
    }
}

EXTENSIONS = [
    '.txt',
    '.json',
    '.yml',
    '.yaml',
    '.cfg',
    '.conf',
    '.ini',
    '.env',
    '.py',
    '.js',
    '.xml',
    '.html',
    '.md',
]
