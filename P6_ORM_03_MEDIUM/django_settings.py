"""
Minimal Django settings for P6_03 testing
Uses SQLite for simplicity - no PostgreSQL required
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SECRET_KEY = 'test-secret-key-for-p6-03-testing'

DEBUG = False  # Disable to prevent SQL logging formatting errors

INSTALLED_APPS = [
    'django.contrib.contenttypes',
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'test_p6_03.db'),
    }
}

USE_TZ = True
