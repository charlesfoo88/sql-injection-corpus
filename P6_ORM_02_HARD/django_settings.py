"""
Minimal Django settings for P6_02 testing
Uses SQLite for simplicity - no PostgreSQL required
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SECRET_KEY = 'test-secret-key-for-p6-02-testing'

DEBUG = True

INSTALLED_APPS = [
    'django.contrib.contenttypes',
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'test_p6_02.db'),
    }
}

USE_TZ = True
