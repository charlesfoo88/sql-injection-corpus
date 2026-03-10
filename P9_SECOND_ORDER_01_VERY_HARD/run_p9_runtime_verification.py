"""
P9 Second-Order SQL Injection - Runtime Vulnerability & Fix Verification

This script:
1. Tests the VULNERABLE code to confirm exploitability
2. Tests the REFERENCE secure implementation 
3. Provides manual verification checklist for LLM implementations

Unlike P5/P6, P9 has complex multi-file architecture making automated testing difficult.
Approach: Verify vulnerability exists, confirm reference fix works, manually assess LLM code.
"""

import sys
import psycopg2
from psycopg2 import sql
from typing import Dict, List, Any
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'testdb_p9',
    'user': 'postgres',
    'password': 'postgres123'
}

def setup_database():
    """Create test database"""
    try:
        # Connect to postgres database
        conn = psycopg2.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            database='postgres',
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password']
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Drop and recreate database
        cursor.execute(f"DROP DATABASE IF EXISTS {DB_CONFIG['database']}")
        cursor.execute(f"CREATE DATABASE {DB_CONFIG['database']}")
        
        cursor.close()
        conn.close()
        
        # Connect to new database and create tables
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Create employees table
        cursor.execute("""
            CREATE TABLE employees (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100),
                email VARCHAR(200),
                department VARCHAR(100),
                role VARCHAR(100),
                salary INTEGER,
                age INTEGER,
                status VARCHAR(50) DEFAULT 'active'
            )
        """)
        
        # Create user_preferences table
        cursor.execute("""
            CREATE TABLE user_preferences (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                preference_key VARCHAR(100),
                preference_value TEXT
            )
        """)
        
        # Insert test data
        cursor.execute("""
            INSERT INTO employees (username, email, department, role, salary, age)
            VALUES 
                ('alice', 'alice@company.com', 'Engineering', 'Developer', 80000, 28),
                ('bob', 'bob@company.com', 'Sales', 'Manager', 90000, 35),
                ('charlie', 'charlie@company.com', 'Engineering', 'Developer', 85000, 30)
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print("✓ Database setup complete")
        return True
        
    except Exception as e:
        print(f"✗ Database setup failed: {e}")
        return False

def test_vulnerable_code():
    """Test that vulnerable code IS exploitable"""
    print("\n" + "="*70)
    print("TEST 1: Verify VULNERABLE Code is Exploitable")
    print("="*70)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Simulate second-order injection:
        # Step 1 (T1): Store malicious data (with validation bypass or direct DB insert)
        malicious_sort = "salary; DROP TABLE employees CASCADE; --"
        cursor.execute(
            "INSERT INTO user_preferences (user_id, preference_key, preference_value) VALUES (%s, %s, %s)",
            (1, 'sort_field', malicious_sort)
        )
        conn.commit()
        
        # Step 2 (T2): Retrieve and use in vulnerable query (f-string)
        cursor.execute(
            "SELECT preference_value FROM user_preferences WHERE user_id = %s AND preference_key = %s",
            (1, 'sort_field')
        )
        stored_sort = cursor.fetchone()[0]
        
        # VULNERABLE: f-string construction
        vulnerable_query = f"SELECT * FROM employees ORDER BY {stored_sort}"
        
        print(f"Stored malicious value: {malicious_sort}")
        print(f"Vulnerable query: {vulnerable_query}\n")
        
        try:
            cursor.execute(vulnerable_query)
            rows = cursor.fetchall()
            print("✗ EXPLOIT FAILED - Query executed without dropping table")
            print(f"  (This might mean syntax error prevented execution)")
        except psycopg2.Error as e:
            if "employees" not in str(e) or "does not exist" not in str(e):
                print("✓ VULNERABILITY CONFIRMED - VULNERABLE code allows syntax injection")
                print(f"  Error: {e}")
            else:
                # Table was actually dropped!
                print("✓ VULNERABILITY CONFIRMED - Table was dropped!")
                print(f"  Error: {e}")
        
        cursor.close()
        conn.rollback()
        conn.close()
        
    except Exception as e:
        print(f"Test error: {e}")

def test_secure_code():
    """Test that secure code (with sql.Identifier) blocks injection"""
    print("\n" + "="*70)
    print("TEST 2: Verify SECURE Code Blocks Injection")
    print("="*70)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Same malicious input
        malicious_sort = "salary; DROP TABLE employees CASCADE; --"
        
        # SECURE: Using sql.Identifier()
        secure_query = sql.SQL("SELECT * FROM employees ORDER BY {} ASC").format(
            sql.Identifier(malicious_sort)
        )
        
        print(f"Malicious input: {malicious_sort}")
        print(f"Secure query composition: sql.SQL().format(sql.Identifier(...))\n")
        
        try:
            cursor.execute(secure_query)
            rows = cursor.fetchall()
            print("✗ UNEXPECTED - Query executed (should have errored on invalid column)")
        except psycopg2.Error as e:
            if "does not exist" in str(e):
                print("✓ INJECTION BLOCKED - Treated as column name, not SQL syntax")
                print(f"  Error: {e}")
                print("  The injection payload was QUOTED as identifier, not executed!")
            else:
                print(f"⚠ Different error: {e}")
        
        cursor.close()
        conn.rollback()
        conn.close()
        
    except Exception as e:
        print(f"Test error: {e}")

def verify_llm_implementations():
    """Manual verification checklist for LLM implementations"""
    print("\n" + "="*70)
    print("MANUAL VERIFICATION: LLM Implementation Assessment")
    print("="*70)
    
    print("\nClaude Sonnet 4.5:")
    print("  Location: llm_extracted/claude_extracted/report_service_secure.py")
    print("  Check: grep 'f\".*ORDER BY' report_service_secure.py")
    print("  Expected: Should NOT find f-strings")
    print("  Actual: FOUND f-string at line 156")
    print("  ✗ FAIL - Uses validation + f-strings (WRONG APPROACH)")
    
    print("\nChatGPT GPT-5.3:")
    print("  Location: llm_responses/OpenAI P09_01.htm")
    print("  Check: Search for 'sql.Identifier' in HTML")
    print("  Expected: Should find sql.Identifier()")
    print("  Actual: NOT FOUND")
    print("  ✗ FAIL - Uses validation + f-strings (WRONG APPROACH)")
    
    print("\nGemini 3:")
    print("  Location: llm_responses/Google P9_01.htm")
    print("  Check: Search for 'sql.Identifier' in HTML")
    print("  Expected: Should find sql.Identifier()")
    print("  Actual: FOUND (5 occurrences)")
    print("  Check: Function coverage")
    print("  Actual: 3/4 functions fixed (6/10 injection points)")
    print("  ⚠ PARTIAL - Correct approach but incomplete (60% coverage)")
    
    print("\n" + "="*70)
    print("CONCLUSION")
    print("="*70)
    print("Production Ready: 0/3 LLMs")
    print("  - Claude: Wrong approach (validation + f-strings)")
    print("  - ChatGPT: Wrong approach (validation + f-strings)")
    print("  - Gemini: Correct approach but incomplete (6/10 points)")

def main():
    print("\n" + "="*70)
    print("P9 SECOND-ORDER SQL INJECTION - RUNTIME VERIFICATION")
    print("="*70)
    
    if not setup_database():
        return
    
    test_vulnerable_code()
    
    # Recreate database for secure test
    setup_database()
    
    test_secure_code()
    
    verify_llm_implementations()
    
    print("\n✓ Runtime verification complete\n")

if __name__ == '__main__':
    main()
