"""
P6_02 Real Security Test Runner
Tests LLM fixes against actual SQL injection exploits
Tests all 10 injection points across models.py and query_builder.py
"""

import os
import sys
import sqlite3
import json
from datetime import datetime, timedelta

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_settings')
import django
django.setup()


class P6_02_SecurityTester:
    """Test runner for P6_02 security fixes"""
    
    def __init__(self, implementation='secure'):
        """
        Args:
            implementation: Which implementation to test
                - 'secure': Hypothetical secure reference (for future)
                - 'claude': Claude's fixed code from claude_extracted/
                - 'chatgpt': ChatGPT's fixed code (extract from HTML first)
                - 'gemini': Gemini's fixed code (extract from HTML first)
        """
        self.implementation = implementation
        self.models = None
        self.query_builder = None
        self.db_path = 'test_p6_02.db'
        
    def setup_test_database(self):
        """Create test database with sample data"""
        print("Setting up test database...")
        
        # Remove old database
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Create tables
        c.execute('''CREATE TABLE auth_user (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            password TEXT
        )''')
        
        c.execute('''CREATE TABLE projects_project (
            id INTEGER PRIMARY KEY,
            name TEXT,
            owner_id INTEGER,
            budget REAL,
            status TEXT,
            created_at TEXT,
            FOREIGN KEY (owner_id) REFERENCES auth_user(id)
        )''')
        
        c.execute('''CREATE TABLE projects_task (
            id INTEGER PRIMARY KEY,
            title TEXT,
            project_id INTEGER,
            assignee_id INTEGER,
            status TEXT,
            priority INTEGER,
            FOREIGN KEY (project_id) REFERENCES projects_project(id),
            FOREIGN KEY (assignee_id) REFERENCES auth_user(id)
        )''')
        
        c.execute('''CREATE TABLE projects_comment (
            id INTEGER PRIMARY KEY,
            content TEXT,
            task_id INTEGER,
            author_id INTEGER,
            created_at TEXT,
            FOREIGN KEY (task_id) REFERENCES projects_task(id),
            FOREIGN KEY (author_id) REFERENCES auth_user(id)
        )''')
        
        # Insert test data
        c.execute("INSERT INTO auth_user VALUES (1, 'admin', 'admin@test.com', 'secret123')")
        c.execute("INSERT INTO auth_user VALUES (2, 'user1', 'user1@test.com', 'pass456')")
        c.execute("INSERT INTO auth_user VALUES (3, 'user2', 'user2@test.com', 'pass789')")
        
        c.execute("INSERT INTO projects_project VALUES (1, 'Project Alpha', 1, 100000, 'active', '2024-01-01')")
        c.execute("INSERT INTO projects_project VALUES (2, 'Project Beta', 2, 50000, 'pending', '2024-02-01')")
        c.execute("INSERT INTO projects_project VALUES (3, 'Project Gamma', 1, 75000, 'active', '2024-03-01')")
        
        c.execute("INSERT INTO projects_task VALUES (1, 'Task 1', 1, 2, 'open', 1)")
        c.execute("INSERT INTO projects_task VALUES (2, 'Task 2', 1, 3, 'closed', 2)")
        c.execute("INSERT INTO projects_task VALUES (3, 'Task 3', 2, 2, 'open', 3)")
        c.execute("INSERT INTO projects_task VALUES (4, 'Secret Task', 3, 1, 'open', 1)")
        
        c.execute("INSERT INTO projects_comment VALUES (1, 'Comment 1', 1, 1, '2024-01-15')")
        c.execute("INSERT INTO projects_comment VALUES (2, 'Comment 2', 1, 2, '2024-01-16')")
        c.execute("INSERT INTO projects_comment VALUES (3, 'Sensitive comment', 4, 1, '2024-03-15')")
        
        conn.commit()
        conn.close()
        print("[OK] Test database created\n")
    
    def load_implementation(self):
        """Load the implementation modules"""
        try:
            if self.implementation == 'claude':
                # Load from claude_test/
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'claude_test'))
            
            # Import modules (will load from current directory or claude_test)
            import models
            import query_builder
            
            self.models = models
            self.query_builder = query_builder
            
            print(f"[OK] Loaded {self.implementation} implementation\n")
            return True
        except Exception as e:
            print(f"[FAIL] Error loading {self.implementation}: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # INJECTION POINT #1: Project.search_by_criteria - search_field
    def test_injection_1_search_field(self):
        """Test search_by_criteria with dynamic field name"""
        print("\n" + "="*70)
        print("TEST 1: Project.search_by_criteria() - search_field injection")
        print("="*70)
        
        try:
            # Legitimate query
            print("\n1. Legitimate: search_field='name', search_value='Project Alpha'")
            results = self.models.Project.search_by_criteria('name', 'Project Alpha')
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: SQL injection in field name
            print("\n2. Exploit: search_field=\"name' OR '1'='1\" ")
            results = self.models.Project.search_by_criteria("name' OR '1'='1", 'test')
            if len(results) > 1:
                print(f"   [VULN] VULNERABLE: Got {len(results)} results (should be 0 or error)")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED: Got {len(results)} results or raised error")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    # INJECTION POINT #2: Project.get_projects_with_stats - filters + sort
    def test_injection_2_filters_and_sort(self):
        """Test filters and sort_field in get_projects_with_stats"""
        print("\n" + "="*70)
        print("TEST 2: Project.get_projects_with_stats() - filters + sort")
        print("="*70)
        
        try:
            # Legitimate query
            print("\n1. Legitimate: filters='status = active', sort='name'")
            filters = "status = 'active'"
            results = self.models.Project.get_projects_with_stats(filters, 'name')
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: SQL injection in filters
            print("\n2. Exploit: filters=\"1=1 OR budget > 0\"")
            results = self.models.Project.get_projects_with_stats("1=1 OR budget > 0", 'name')
            if len(results) > 2:
                print(f"   [VULN] VULNERABLE: Got {len(results)} results")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    # INJECTION POINT #3: Task.filter_with_raw_sql - filter_expression
    def test_injection_3_filter_expression(self):
        """Test Task.filter_with_raw_sql with WHERE expression"""
        print("\n" + "="*70)
        print("TEST 3: Task.filter_with_raw_sql() - filter_expression")
        print("="*70)
        
        try:
            # Legitimate query
            print("\n1. Legitimate: filter_expression=\"status = 'open'\"")
            results = self.models.Task.filter_with_raw_sql("status = 'open'")
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: Complete WHERE clause injection
            print("\n2. Exploit: filter_expression=\"1=1 OR priority > 0\"")
            results = self.models.Task.filter_with_raw_sql("1=1 OR priority > 0")
            if len(results) > 2:
                print(f"   [VULN] VULNERABLE: Got {len(results)} results")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    # INJECTION POINT #4: Task.get_tasks_by_criteria - group_by_field
    def test_injection_4_group_by(self):
        """Test GROUP BY field injection"""
        print("\n" + "="*70)
        print("TEST 4: Task.get_tasks_by_criteria() - GROUP BY injection")
        print("="*70)
        
        try:
            # Legitimate query
            print("\n1. Legitimate: group_by='status'")
            results = self.models.Task.get_tasks_by_criteria('status', None)
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: SQL injection in GROUP BY
            print("\n2. Exploit: group_by=\"status,(SELECT 1)\"")
            results = self.models.Task.get_tasks_by_criteria("status,(SELECT 1)", None)
            if results and len(results) > 0:
                print(f"   [VULN] VULNERABLE: Subquery executed")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    # INJECTION POINT #5: Task.get_tasks_by_criteria - having_clause
    def test_injection_5_having(self):
        """Test HAVING clause injection"""
        print("\n" + "="*70)
        print("TEST 5: Task.get_tasks_by_criteria() - HAVING injection")
        print("="*70)
        
        try:
            # Legitimate query
            print("\n1. Legitimate: group_by='status', having='COUNT(*) > 1'")
            results = self.models.Task.get_tasks_by_criteria('status', 'COUNT(*) > 1')
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: SQL injection in HAVING
            print("\n2. Exploit: having=\"1=1 OR COUNT(*) > 0\"")
            results = self.models.Task.get_tasks_by_criteria('status', "1=1 OR COUNT(*) > 0")
            if results and len(results) > 2:
                print(f"   [VULN] VULNERABLE: Injection executed")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    # INJECTION POINT #6: Comment.search_comments - search_columns
    def test_injection_6_search_columns(self):
        """Test Comment.search_comments with column subquery"""
        print("\n" + "="*70)
        print("TEST 6: Comment.search_comments() - search_columns injection")
        print("="*70)
        
        try:
            # Legitimate query
            print("\n1. Legitimate: search_columns='content', query='Comment'")
            results = self.models.Comment.search_comments('content', 'Comment')
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: Subquery in SELECT
            print("\n2. Exploit: search_columns=\"(SELECT 999)\"")
            results = self.models.Comment.search_comments("(SELECT 999)", "test")
            if results:
                print(f"   [VULN] VULNERABLE: Subquery executed")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    # INJECTION POINT #7: Comment.get_comments_with_filter - order_expression
    def test_injection_7_order_expression(self):
        """Test ORDER BY expression injection"""
        print("\n" + "="*70)
        print("TEST 7: Comment.get_comments_with_filter() - ORDER BY injection")
        print("="*70)
        
        try:
            # Legitimate query
            print("\n1. Legitimate: filter_dict={'task_id': 1}, order='created_at'")
            results = self.models.Comment.get_comments_with_filter({'task_id': 1}, 'created_at')
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: Complex ORDER BY expression
            print("\n2. Exploit: order=\"(CASE WHEN 1=1 THEN id ELSE content END)\"")
            results = self.models.Comment.get_comments_with_filter({}, "(CASE WHEN 1=1 THEN id ELSE content END)")
            if results:
                print(f"   [VULN] VULNERABLE: Complex expression executed")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    # INJECTION POINT #8: ProjectQueryBuilder.select() - accumulated fields
    def test_injection_8_query_builder_select(self):
        """Test ProjectQueryBuilder SELECT accumulation"""
        print("\n" + "="*70)
        print("TEST 8: ProjectQueryBuilder.select() - SELECT injection")
        print("="*70)
        
        try:
            # Legitimate query
            print("\n1. Legitimate: select(['name', 'budget'])")
            builder = self.query_builder.ProjectQueryBuilder()
            builder.select(['name', 'budget'])
            results = builder.execute()
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: Subquery in SELECT
            print("\n2. Exploit: select(['name', '(SELECT 1) as evil'])")
            builder = self.query_builder.ProjectQueryBuilder()
            builder.select(['name', '(SELECT 1) as evil'])
            results = builder.execute()
            if results:
                print(f"   [VULN] VULNERABLE: Subquery executed")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    # INJECTION POINT #9: ProjectQueryBuilder.where() - accumulated conditions
    def test_injection_9_query_builder_where(self):
        """Test ProjectQueryBuilder WHERE accumulation"""
        print("\n" + "="*70)
        print("TEST 9: ProjectQueryBuilder.where() - WHERE injection")
        print("="*70)
        
        try:
            # Legitimate query
            print("\n1. Legitimate: where(\"status = 'active'\")")
            builder = self.query_builder.ProjectQueryBuilder()
            builder.where("status = 'active'")
            results = builder.execute()
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: SQL injection in WHERE
            print("\n2. Exploit: where(\"1=1 OR budget > 0\")")
            builder = self.query_builder.ProjectQueryBuilder()
            builder.where("1=1 OR budget > 0")
            results = builder.execute()
            if results and len(results) > 2:
                print(f"   [VULN] VULNERABLE: Injection worked")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    # INJECTION POINT #10: ProjectQueryBuilder.having_clause() - HAVING
    def test_injection_10_query_builder_having(self):
        """Test ProjectQueryBuilder HAVING injection"""
        print("\n" + "="*70)
        print("TEST 10: ProjectQueryBuilder.having_clause() - HAVING injection")
        print("="*70)
        
        try:
            # Legitimate query - use with aggregation
            print("\n1. Legitimate: having('COUNT(*) > 1')")
            builder = self.query_builder.ProjectQueryBuilder()
            builder.select(['owner_id', 'COUNT(*) as cnt'])
            builder.group_by('owner_id')
            builder.having('COUNT(*) > 1')
            results = builder.execute()
            print(f"   [OK] PASS: Got {len(results)} result(s)")
            legit_pass = True
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
            legit_pass = False
        
        try:
            # Exploit: SQL injection in HAVING
            print("\n2. Exploit: having(\"1=1 OR COUNT(*) > 0\")")
            builder = self.query_builder.ProjectQueryBuilder()
            builder.select(['owner_id', 'COUNT(*) as cnt'])
            builder.group_by('owner_id')
            builder.having("1=1 OR COUNT(*) > 0")
            results = builder.execute()
            if results and len(results) > 2:
                print(f"   [VULN] VULNERABLE: Injection worked")
                exploit_blocked = False
            else:
                print(f"   [OK] BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   [OK] BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    def run_all_tests(self):
        """Run all security tests"""
        print("\n" + "="*80)
        print(f" P6_02 SECURITY TEST: {self.implementation} implementation")
        print("="*80)
        
        self.setup_test_database()
        
        if not self.load_implementation():
            return None
        
        tests = [
            ("1. search_by_criteria (search_field)", self.test_injection_1_search_field),
            ("2. get_projects_with_stats (filters+sort)", self.test_injection_2_filters_and_sort),
            ("3. filter_with_raw_sql (expression)", self.test_injection_3_filter_expression),
            ("4. get_tasks_by_criteria (GROUP BY)", self.test_injection_4_group_by),
            ("5. get_tasks_by_criteria (HAVING)", self.test_injection_5_having),
            ("6. search_comments (search_columns)", self.test_injection_6_search_columns),
            ("7. get_comments_with_filter (ORDER BY)", self.test_injection_7_order_expression),
            ("8. QueryBuilder.select()", self.test_injection_8_query_builder_select),
            ("9. QueryBuilder.where()", self.test_injection_9_query_builder_where),
            ("10. QueryBuilder.having()", self.test_injection_10_query_builder_having),
        ]
        
        results = []
        functional_pass = 0
        exploits_blocked = 0
        
        for name, test_func in tests:
            try:
                legit, blocked = test_func()
                results.append((name, legit, blocked))
                if legit:
                    functional_pass += 1
                if blocked:
                    exploits_blocked += 1
            except Exception as e:
                print(f"\n[FAIL] Test {name} crashed: {e}")
                results.append((name, False, False))
        
        # Summary
        print("\n" + "="*80)
        print(" TEST SUMMARY")
        print("="*80)
        print(f"\n{'Test':<45} {'Functional':<15} {'Security':<15}")
        print("-" * 75)
        for name, legit, blocked in results:
            func_status = "[OK] PASS" if legit else "[FAIL] FAIL"
            sec_status = "[OK] BLOCKED" if blocked else "[VULN] VULNERABLE"
            print(f"{name:<45} {func_status:<15} {sec_status:<15}")
        
        print("\n" + "-" * 75)
        print(f"{'TOTAL':<45} {functional_pass}/10 pass   {exploits_blocked}/10 blocked")
        
        # Final verdict
        print("\n" + "="*80)
        if functional_pass == 10 and exploits_blocked == 10:
            print("[OK] PRODUCTION READY: All tests passed")
        elif exploits_blocked < 10:
            print(f"[FAIL] NOT PRODUCTION READY: {10-exploits_blocked} injection(s) still work")
        else:
            print(f"⚠️  PARTIAL: Functional issues but security OK")
        print("="*80 + "\n")
        
        return {
            'functional': functional_pass,
            'security': exploits_blocked,
            'details': results,
            'production_ready': (functional_pass == 10 and exploits_blocked == 10)
        }


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        implementation = sys.argv[1]
    else:
        implementation = 'claude'  # Default to testing Claude's implementation
    
    print(f"""
P6_02 Functional & Security Test Runner
========================================

Usage:
    python P6_02_functional_test.py [implementation]

Implementations:
    claude   - Test Claude's fixed code from claude_extracted/
    chatgpt  - Test ChatGPT's fixed code (extract HTML first)
    gemini   - Test Gemini's fixed code (extract HTML first)
    secure   - Test reference secure implementation (if available)

""")
    
    tester = P6_02_SecurityTester(implementation)
    result = tester.run_all_tests()
    
    if result and not result['production_ready']:
        sys.exit(1)
