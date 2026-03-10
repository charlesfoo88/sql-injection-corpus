"""
Set up test database for P6_01 testing
Creates Article table and populates with test data
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_settings')
sys.path.insert(0, os.path.dirname(__file__))
django.setup()

from django.db import connection

def create_test_database():
    """Create articles table and populate with test data"""
    
    with connection.cursor() as cursor:
        # Drop existing table if any
        cursor.execute("DROP TABLE IF EXISTS articles")
        
        # Create articles table
        cursor.execute("""
            CREATE TABLE articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title VARCHAR(200) NOT NULL,
                content TEXT NOT NULL,
                author VARCHAR(100) NOT NULL,
                category VARCHAR(50) NOT NULL,
                tags VARCHAR(200) NOT NULL,
                published_date DATE NOT NULL,
                views INTEGER DEFAULT 0
            )
        """)
        
        # Insert test data
        test_data = [
            ('Python Best Practices', 'Content about Python...', 'John Doe', 'technology', 'python,coding', '2024-01-15', 150),
            ('Django Security Guide', 'Security tips for Django...', 'Jane Smith', 'technology', 'django,security,python', '2024-02-01', 220),
            ('SQL Injection Basics', 'Understanding SQL attacks...', 'John Doe', 'security', 'sql,security', '2024-01-20', 180),
            ('Web Development Tips', 'Modern web dev techniques...', 'Alice Johnson', 'technology', 'web,javascript', '2024-02-05', 95),
            ('Database Design', 'Principles of good DB design...', 'Bob Wilson', 'database', 'sql,database', '2024-01-10', 200),
            ('Admin Panel Guide', 'Building secure admin panels...', 'admin', 'security', 'admin,security', '2024-02-08', 50),
        ]
        
        cursor.executemany("""
            INSERT INTO articles (title, content, author, category, tags, published_date, views)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, test_data)
        
        connection.commit()
        
    print("✅ Test database created successfully")
    print(f"   Database: {connection.settings_dict['NAME']}")
    print(f"   Articles: {len(test_data)} test records inserted")

if __name__ == '__main__':
    create_test_database()
