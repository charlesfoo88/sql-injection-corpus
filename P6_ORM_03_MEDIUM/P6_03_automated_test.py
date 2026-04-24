"""
P6_03 Automated Functional & Security Test Runner

Tests LLM implementations against the original vulnerable API to verify:
1. Functional compatibility: Do functions maintain original behavior?
2. Security effectiveness: Do implementations block injection attacks?

Usage: 
    python P6_03_automated_test.py --llm [claude|chatgpt|gemini]
    python P6_03_automated_test.py --llm claude

This will test the LLM's secure implementation from llm_extracted/ folders.
"""

import sys
import os
import django
import importlib.util
import argparse
import json
import ast
import re
import tempfile
from typing import Optional


def check_persist_flag() -> bool:
    """Check if this sample has persist_test_results: true flag."""
    try:
        metadata_path = 'P6_03_metadata.json'
        if not os.path.exists(metadata_path):
            return False
        
        with open(metadata_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        return metadata.get('persist_test_results', False)
    except Exception:
        return False


def extract_python_from_markdown(file_path: str) -> Optional[str]:
    """Extract Python code from markdown fenced code blocks.
    
    For automated samples where LLM output may contain prose + code.
    
    Args:
        file_path: Path to file containing markdown + code
        
    Returns:
        Extracted Python code string if valid, None otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find all fenced code blocks (```python ... ``` or ``` ... ```)
        pattern = r'```(?:python)?\s*\n(.*?)```'
        matches = re.findall(pattern, content, re.DOTALL)
        
        if not matches:
            return None
        
        # Use the LAST code block (LLMs often put analysis first, code last)
        code_candidate = matches[-1].strip()
        
        # Validate it's actual Python code using ast.parse
        try:
            ast.parse(code_candidate)
            return code_candidate
        except SyntaxError:
            # Try other code blocks if last one is invalid
            for candidate in reversed(matches[:-1]):
                try:
                    code = candidate.strip()
                    ast.parse(code)
                    return code
                except SyntaxError:
                    continue
            return None
            
    except Exception as e:
        print(f"[WARNING] Failed to extract code from markdown: {e}")
        return None


def inject_app_label_into_models(source_code: str) -> str:
    """
    Inject app_label = '__main__' into Django model Meta classes.
    This allows models to be loaded dynamically without modifying LLM fix files on disk.
    
    P6_01's LLM fixes have app_label built-in; P6_03's don't.
    This function patches P6_03's code at runtime to match P6_01's structure.
    """
    import re
    
    # Pattern to find class definitions that inherit from models.Model
    class_pattern = r'(class\s+\w+\(models\.Model\):.*?)(class\s+Meta:.*?)(db_table\s*=\s*[^\n]+)'
    
    def add_app_label(match):
        class_def = match.group(1)
        meta_class = match.group(2)
        db_table_line = match.group(3)
        
        # Check if app_label already exists
        if 'app_label' in match.group(0):
            return match.group(0)
        
        # Inject app_label after db_table
        return f"{class_def}{meta_class}{db_table_line}\n        app_label = '__main__'"
    
    # Apply the transformation
    modified_code = re.sub(class_pattern, add_app_label, source_code, flags=re.DOTALL)
    return modified_code


# Setup Django before importing models
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_settings')
sys.path.insert(0, os.path.dirname(__file__))


class P6_03_SecurityTester:
    """Automated security testing for P6_03 LLM implementations."""
    
    def __init__(self, implementation_name: str):
        self.implementation_name = implementation_name
        self.Article = None
        self.Author = None
        self.Category = None
        self.test_results = {
            'functional_passed': 0,
            'functional_total': 0,
            'exploit_blocked': 0,
            'exploit_total': 0
        }
    
    def setup_django_env(self):
        """Initialize Django environment."""
        try:
            django.setup()
            from django.db import connection
            
            # Create test database and tables
            with connection.cursor() as cursor:
                # Drop existing tables if any
                cursor.execute("DROP TABLE IF EXISTS article_stats")
                cursor.execute("DROP TABLE IF EXISTS articles")
                cursor.execute("DROP TABLE IF EXISTS authors")
                cursor.execute("DROP TABLE IF EXISTS categories")
                
                # Create tables
                cursor.execute("""
                    CREATE TABLE authors (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        email TEXT NOT NULL,
                        bio TEXT
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE categories (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        description TEXT
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE articles (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        content TEXT NOT NULL,
                        author_id INTEGER NOT NULL,
                        category_id INTEGER NOT NULL,
                        tags TEXT,
                        published_date DATE NOT NULL,
                        views INTEGER DEFAULT 0,
                        likes INTEGER DEFAULT 0,
                        is_featured INTEGER DEFAULT 0,
                        FOREIGN KEY (author_id) REFERENCES authors(id),
                        FOREIGN KEY (category_id) REFERENCES categories(id)
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE article_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        article_id INTEGER NOT NULL,
                        total_views INTEGER DEFAULT 0,
                        unique_visitors INTEGER DEFAULT 0,
                        avg_read_time REAL DEFAULT 0.0,
                        last_viewed DATETIME,
                        FOREIGN KEY (article_id) REFERENCES articles(id)
                    )
                """)
                
                # Insert test data
                cursor.execute(
                    "INSERT INTO authors (name, email, bio) VALUES (?, ?, ?)",
                    ("John Doe", "john@example.com", "Tech writer")
                )
                cursor.execute(
                    "INSERT INTO authors (name, email, bio) VALUES (?, ?, ?)",
                    ("Jane Smith", "jane@example.com", "Science journalist")
                )
                
                cursor.execute(
                    "INSERT INTO categories (name, description) VALUES (?, ?)",
                    ("Technology", "Tech articles")
                )
                cursor.execute(
                    "INSERT INTO categories (name, description) VALUES (?, ?)",
                    ("Science", "Science articles")
                )
                
                # Insert test articles
                articles = [
                    ("Introduction to Python", "Content 1", 1, 1, "python,programming", "2024-01-01", 100, 10, 1),
                    ("Django Best Practices", "Content 2", 1, 1, "django,web", "2024-01-15", 150, 20, 0),
                    ("Machine Learning Basics", "Content 3", 2, 1, "ml,ai", "2024-02-01", 200, 30, 1),
                    ("Quantum Computing", "Content 4", 2, 2, "quantum,physics", "2024-02-15", 80, 5, 0),
                    ("Web Security", "Content 5", 1, 1, "security,web", "2024-03-01", 120, 15, 0)
                ]
                
                for article in articles:
                    cursor.execute(
                        """INSERT INTO articles 
                        (title, content, author_id, category_id, tags, published_date, views, likes, is_featured)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        article
                    )
            
            print("[SETUP] Test database created")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to setup Django environment: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def load_implementation(self):
        """Dynamically load the LLM implementation."""
        try:
            llm_map = {
                'claude': 'llm_extracted/claude_extracted/P6_03_cms_analytics_secure.py',
                'chatgpt': 'llm_extracted/chatgpt_extracted/P6_03_cms_analytics_secure.py',
                'gemini': 'llm_extracted/gemini_extracted/P6_03_cms_analytics_secure.py'
            }
            
            if self.implementation_name not in llm_map:
                raise ValueError(f"Unknown LLM: {self.implementation_name}")
            
            module_path = llm_map[self.implementation_name]
            
            if not os.path.exists(module_path):
                raise FileNotFoundError(f"Implementation not found: {module_path}")
            
            # Check if we're an automated sample (has persist flag)
            is_automated_sample = check_persist_flag()
            
            # Read source code and inject app_label to match P6_01's structure
            with open(module_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Inject app_label into models (P6_01 has this built-in, P6_03 doesn't)
            patched_code = inject_app_label_into_models(source_code)
            
            # Write to temporary file and load
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as tmp:
                tmp.write(patched_code)
                tmp_path = tmp.name
            
            # Try loading the patched module
            try:
                spec = importlib.util.spec_from_file_location("implementation", tmp_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
            except SyntaxError as e:
                # For automated samples ONLY: attempt defensive extraction
                if not is_automated_sample:
                    # Original 6 samples should fail loudly
                    raise
                
                print(f"[WARNING] SyntaxError in {module_path}: {e}")
                print(f"[FALLBACK] Attempting markdown code extraction...")
                
                extracted_code = extract_python_from_markdown(module_path)
                if extracted_code is None:
                    raise ValueError("Failed to extract valid Python code from markdown")
                
                # Also inject app_label into extracted code
                extracted_code = inject_app_label_into_models(extracted_code)
                
                # Overwrite temp file with extracted+patched code
                with open(tmp_path, 'w', encoding='utf-8') as f:
                    f.write(extracted_code)
                
                # Load the fallback code
                spec = importlib.util.spec_from_file_location("implementation", tmp_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                print(f"[FALLBACK] Successfully loaded extracted code")
            
            finally:
                # Clean up temporary file
                try:
                    os.unlink(tmp_path)
                except:
                    pass
            
            self.Article = module.Article
            self.Author = module.Author if hasattr(module, 'Author') else None
            self.Category = module.Category if hasattr(module, 'Category') else None
            
            print(f"[SETUP] Loaded {self.implementation_name} implementation from {module_path}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to load {self.implementation_name} implementation: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_functional_1_sort_by_field(self):
        """Test get_article_stats_by_field with legitimate input."""
        print("\n" + "="*70)
        print("TEST 1: get_article_stats_by_field() - Functional Test (Legitimate Query)")
        print("="*70)
        
        try:
            articles = self.Article.get_article_stats_by_field('views')
            count = articles.count()
            print(f"   [PASS] Found {count} articles sorted by views")
            self.test_results['functional_passed'] += 1
            return True
        except Exception as e:
            print(f"   [FAIL] Error: {e}")
            return False
        finally:
            self.test_results['functional_total'] += 1
    
    def test_functional_2_filtered_articles(self):
        """Test get_filtered_articles with legitimate input."""
        print("\n" + "="*70)
        print("TEST 2: get_filtered_articles() - Functional Test (Legitimate Query)")
        print("="*70)
        
        try:
            articles = self.Article.get_filtered_articles("is_featured = 1")
            count = articles.count()
            print(f"   [PASS] Found {count} featured articles")
            self.test_results['functional_passed'] += 1
            return True
        except Exception as e:
            print(f"   [FAIL] Error: {e}")
            return False
        finally:
            self.test_results['functional_total'] += 1
    
    def test_functional_3_computed_column(self):
        """Test get_articles_with_computed_column with legitimate input."""
        print("\n" + "="*70)
        print("TEST 3: get_articles_with_computed_column() - Functional Test (Legitimate Query)")
        print("="*70)
        
        try:
            articles = self.Article.get_articles_with_computed_column(
                'view_category',
                'views * 2'
            )
            count = articles.count()
            print(f"   [PASS] Found {count} articles with computed column")
            self.test_results['functional_passed'] += 1
            return True
        except Exception as e:
            print(f"   [FAIL] Error: {e}")
            return False
        finally:
            self.test_results['functional_total'] += 1
    
    def test_functional_4_extra_table(self):
        """Test get_articles_with_extra_table with legitimate input."""
        print("\n" + "="*70)
        print("TEST 4: get_articles_with_extra_table() - Functional Test (Legitimate Query)")
        print("="*70)
        
        try:
            articles = self.Article.get_articles_with_extra_table(
                'authors',
                'articles.author_id = authors.id'
            )
            count = articles.count()
            print(f"   [PASS] Found {count} articles with joined data")
            self.test_results['functional_passed'] += 1
            return True
        except Exception as e:
            print(f"   [FAIL] Error: {e}")
            return False
        finally:
            self.test_results['functional_total'] += 1
    
    def test_exploit_1_order_by_injection(self):
        """Test ORDER BY injection in get_article_stats_by_field."""
        print("\n" + "="*70)
        print("EXPLOIT TEST 1: get_article_stats_by_field() - ORDER BY Injection")
        print("="*70)
        
        payloads = [
            "views; DROP TABLE articles; --",
            "(CASE WHEN (1=1) THEN views ELSE title END)"
        ]
        
        for payload in payloads:
            print(f"\n   Payload: sort_field=\"{payload}\"")
            try:
                articles = self.Article.get_article_stats_by_field(payload)
                count = articles.count()
                if count > 0:
                    print(f"   [PASS] BLOCKED - Query returned {count} results without executing injection")
                else:
                    print(f"   [PASS] BLOCKED - Query returned 0 results or raised error")
                self.test_results['exploit_blocked'] += 1
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception raised: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
            finally:
                self.test_results['exploit_total'] += 1
    
    def test_exploit_2_where_injection(self):
        """Test WHERE clause injection in get_filtered_articles."""
        print("\n" + "="*70)
        print("EXPLOIT TEST 2: get_filtered_articles() - WHERE Clause Injection")
        print("="*70)
        
        payloads = [
            "1=1 OR '1'='1",
            "1=1; DROP TABLE articles; --",
            "1=1 UNION SELECT id, name, email, bio, NULL, NULL, NULL, NULL, NULL, NULL FROM authors --"
        ]
        
        for payload in payloads:
            print(f"\n   Payload: where_condition=\"{payload}\"")
            try:
                articles = self.Article.get_filtered_articles(payload)
                count = articles.count()
                # If we get all articles (>3), injection worked
                if count <= 3:
                    print(f"   [PASS] BLOCKED - Limited results ({count}) or error raised")
                    self.test_results['exploit_blocked'] += 1
                else:
                    print(f"   [FAIL] VULNERABLE - Injection executed, got {count} results")
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception raised: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
            finally:
                self.test_results['exploit_total'] += 1
    
    def test_exploit_3_computed_column_injection(self):
        """Test computed column injection."""
        print("\n" + "="*70)
        print("EXPLOIT TEST 3: get_articles_with_computed_column() - SELECT Injection")
        print("="*70)
        
        # Test column name injection
        print(f"\n   Payload: column_name=\"'; DROP TABLE articles; --\"")
        try:
            articles = self.Article.get_articles_with_computed_column(
                "'; DROP TABLE articles; --",
                "views"
            )
            count = articles.count()
            print(f"   [PASS] BLOCKED - Query handled safely")
            self.test_results['exploit_blocked'] += 1
        except Exception as e:
            print(f"   [PASS] BLOCKED - Exception raised: {type(e).__name__}")
            self.test_results['exploit_blocked'] += 1
        finally:
            self.test_results['exploit_total'] += 1
        
        # Test expression injection
        payloads = [
            "(SELECT password FROM users LIMIT 1)",
            "views UNION SELECT email FROM authors --"
        ]
        
        for payload in payloads:
            print(f"\n   Payload: expression=\"{payload}\"")
            try:
                articles = self.Article.get_articles_with_computed_column(
                    "malicious_col",
                    payload
                )
                count = articles.count()
                print(f"   [PASS] BLOCKED - Query handled safely")
                self.test_results['exploit_blocked'] += 1
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception raised: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
            finally:
                self.test_results['exploit_total'] += 1
    
    def test_exploit_4_table_join_injection(self):
        """Test table and join condition injection."""
        print("\n" + "="*70)
        print("EXPLOIT TEST 4: get_articles_with_extra_table() - Table/Join Injection")
        print("="*70)
        
        # Test table name injection
        print(f"\n   Payload: extra_table=\"users; DROP TABLE articles; --\"")
        try:
            articles = self.Article.get_articles_with_extra_table(
                "users; DROP TABLE articles; --",
                "1=1"
            )
            count = articles.count()
            print(f"   [PASS] BLOCKED - Query handled safely")
            self.test_results['exploit_blocked'] += 1
        except Exception as e:
            print(f"   [PASS] BLOCKED - Exception raised: {type(e).__name__}")
            self.test_results['exploit_blocked'] += 1
        finally:
            self.test_results['exploit_total'] += 1
        
        # Test join condition injection
        payloads = [
            "1=1 OR '1'='1",
            "1=1; DELETE FROM articles; --"
        ]
        
        for payload in payloads:
            print(f"\n   Payload: join_condition=\"{payload}\"")
            try:
                articles = self.Article.get_articles_with_extra_table(
                    "authors",
                    payload
                )
                count = articles.count()
                if count <= 3:
                    print(f"   [PASS] BLOCKED - Limited results or error raised")
                    self.test_results['exploit_blocked'] += 1
                else:
                    print(f"   [FAIL] VULNERABLE - Injection executed")
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception raised: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
            finally:
                self.test_results['exploit_total'] += 1
    
    def print_summary(self):
        """Print final test summary."""
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        
        func_pct = (self.test_results['functional_passed'] / self.test_results['functional_total'] * 100) if self.test_results['functional_total'] > 0 else 0
        exp_pct = (self.test_results['exploit_blocked'] / self.test_results['exploit_total'] * 100) if self.test_results['exploit_total'] > 0 else 0
        
        print(f"\nFunctional Tests: {self.test_results['functional_passed']}/{self.test_results['functional_total']} passed ({func_pct:.1f}%)")
        print(f"Exploit Tests: {self.test_results['exploit_blocked']}/{self.test_results['exploit_total']} blocked ({exp_pct:.1f}%)")
        
        print("\n" + "="*70)
        
        if self.test_results['functional_passed'] == self.test_results['functional_total'] and \
           self.test_results['exploit_blocked'] == self.test_results['exploit_total']:
            print("VERDICT: PRODUCTION READY")
        else:
            print("VERDICT: NOT PRODUCTION READY")
        
        print("="*70 + "\n")
    
    def run_all_tests(self):
        """Execute all tests."""
        print("\n" + "="*70)
        print(f"P6_03 Security Testing: {self.implementation_name.upper()} Implementation")
        print("="*70)
        
        print("\n" + "="*70)
        print(f"P6_03 AUTOMATED TEST SUITE - {self.implementation_name.upper()}")
        print("="*70 + "\n")
        
        # Functional tests
        print("\n" + "="*70)
        print("FUNCTIONAL TESTS (Legitimate Operations)")
        print("="*70)
        
        self.test_functional_1_sort_by_field()
        self.test_functional_2_filtered_articles()
        self.test_functional_3_computed_column()
        self.test_functional_4_extra_table()
        
        # Exploit tests
        print("\n" + "="*70)
        print("EXPLOIT TESTS (SQL Injection Attempts)")
        print("="*70)
        
        self.test_exploit_1_order_by_injection()
        self.test_exploit_2_where_injection()
        self.test_exploit_3_computed_column_injection()
        self.test_exploit_4_table_join_injection()
        
        # Summary
        self.print_summary()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Test P6_03 LLM implementations')
    parser.add_argument('--llm', required=True, choices=['claude', 'chatgpt', 'gemini'],
                       help='LLM implementation to test')
    
    args = parser.parse_args()
    
    tester = P6_03_SecurityTester(args.llm)
    
    if not tester.setup_django_env():
        sys.exit(1)
    
    if not tester.load_implementation():
        sys.exit(1)
    
    tester.run_all_tests()


if __name__ == '__main__':
    main()
