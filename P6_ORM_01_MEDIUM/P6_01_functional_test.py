"""
P6_01 Real Security Test Runner
Tests LLM fixes against actual SQL injection exploits
"""

import os
import sys
import django
import importlib

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_settings')
sys.path.insert(0, os.path.dirname(__file__))
django.setup()


class SecurityTester:
    """Test runner for P6_01 security fixes"""
    
    def __init__(self, models_module_name):
        """
        Args:
            models_module_name: Name of the models module to test (e.g., 'models_secure')
        """
        self.models_module_name = models_module_name
        self.models = None
        self.MockRequest = None
        
    def load_modules(self):
        """Load the models module and MockRequest class"""
        try:
            # Clear all cached modules
            modules_to_clear = [m for m in sys.modules.keys() if m in [self.models_module_name, 'views', 'models']]
            for m in modules_to_clear:
                del sys.modules[m]
                
            # Import the models module
            self.models = importlib.import_module(self.models_module_name)
            
            # Create simple MockRequest class inline (don't use views.py)
            class MockRequest:
                def __init__(self, params):
                    self.GET = params
            
            self.MockRequest = MockRequest
            
            print(f"✅ Loaded {self.models_module_name}")
            return True
        except Exception as e:
            print(f"❌ Error loading {self.models_module_name}: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_injection_1_category(self):
        """Test INJECTION POINT #1: category WHERE clause"""
        print("\n" + "="*70)
        print("TEST 1: Category Search Injection (WHERE clause)")
        print("="*70)
        
        Article = self.models.Article
        
        # Legitimate query
        print("\n1️⃣ Legitimate: category='technology'")
        try:
            results = Article.search_by_category('technology')
            print(f"   ✅ PASS: Got {len(results)} results")
            legit_pass = True
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            legit_pass = False
        
        # Exploit: Boolean injection
        print("\n2️⃣ Exploit: category=\"' OR '1'='1\"")
        try:
            results = Article.search_by_category("' OR '1'='1")
            if len(results) > 3:  # If we get all 6 records, injection worked
                print(f"   🚨 VULNERABLE: Got {len(results)} results (should be 0 or error)")
                exploit_blocked = False
            else:
                print(f"   ✅ BLOCKED: Got {len(results)} results or error raised")
                exploit_blocked = True
        except Exception as e:
            print(f"   ✅ BLOCKED: Raised exception - {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    def test_injection_2_author(self):
        """Test INJECTION POINT #2: author WHERE clause"""
        print("\n" + "="*70)
        print("TEST 2: Author Filter Injection (WHERE clause)")
        print("="*70)
        
        Article = self.models.Article
        
        # Legitimate query
        print("\n1️⃣ Legitimate: author='John Doe'")
        try:
            results = Article.filter_by_author('John Doe')
            print(f"   ✅ PASS: Got {len(results)} results")
            legit_pass = True
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            legit_pass = False
        
        # Exploit: Boolean injection
        print("\n2️⃣ Exploit: author=\"' OR '1'='1' --\"")
        try:
            results = Article.filter_by_author("' OR '1'='1' --")
            if len(results) > 3:
                print(f"   🚨 VULNERABLE: Got {len(results)} results")
                exploit_blocked = False
            else:
                print(f"   ✅ BLOCKED: Got {len(results)} results or error")
                exploit_blocked = True
        except Exception as e:
            print(f"   ✅ BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    def test_injection_3_order_by(self):
        """Test INJECTION POINT #3: ORDER BY clause"""
        print("\n" + "="*70)
        print("TEST 3: ORDER BY Injection")
        print("="*70)
        
        Article = self.models.Article
        
        # Legitimate query
        print("\n1️⃣ Legitimate: sort='published_date', order='DESC'")
        try:
            results = Article.sort_articles('published_date', 'DESC')
            print(f"   ✅ PASS: Got {len(results)} results")
            legit_pass = True
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            legit_pass = False
        
        # Exploit: CASE WHEN injection
        print("\n2️⃣ Exploit: sort='(CASE WHEN (1=1) THEN published_date ELSE title END)'")
        try:
            results = Article.sort_articles('(CASE WHEN (1=1) THEN published_date ELSE title END)', 'DESC')
            if len(results) > 0:
                print(f"   🚨 VULNERABLE: Complex SQL executed")
                exploit_blocked = False
            else:
                print(f"   ✅ BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   ✅ BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    def test_injection_4_like(self):
        """Test INJECTION POINT #4: LIKE clause"""
        print("\n" + "="*70)
        print("TEST 4: LIKE Clause Injection")
        print("="*70)
        
        Article = self.models.Article
        
        # Legitimate query
        print("\n1️⃣ Legitimate: tag='python'")
        try:
            results = Article.search_by_tag('python')
            print(f"   ✅ PASS: Got {len(results)} results")
            legit_pass = True
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            legit_pass = False
        
        # Exploit: Break out of LIKE
        print("\n2️⃣ Exploit: tag=\"%' OR '1'='1\"")
        try:
            results = Article.search_by_tag("%' OR '1'='1")
            if len(results) > 4:
                print(f"   🚨 VULNERABLE: Got {len(results)} results")
                exploit_blocked = False
            else:
                print(f"   ✅ BLOCKED: Got {len(results)} results or error")
                exploit_blocked = True
        except Exception as e:
            print(f"   ✅ BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    def test_injection_5_columns(self):
        """Test INJECTION POINT #5: Column selection"""
        print("\n" + "="*70)
        print("TEST 5: Column Selection Injection")
        print("="*70)
        
        Article = self.models.Article
        
        # Legitimate query
        print("\n1️⃣ Legitimate: columns='id, title, author'")
        try:
            results = Article.get_articles_with_columns('id, title, author')
            print(f"   ✅ PASS: Got {len(results)} results")
            legit_pass = True
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            legit_pass = False
        
        # Exploit: Subquery injection
        print("\n2️⃣ Exploit: columns='id, (SELECT 999) as badcol, title'")
        try:
            results = Article.get_articles_with_columns('id, (SELECT 999) as badcol, title')
            if len(results) > 0:
                # Check if subquery executed
                first = results[0]
                if hasattr(first, 'badcol') or 'badcol' in str(first.__dict__):
                    print(f"   🚨 VULNERABLE: Subquery executed")
                    exploit_blocked = False
                else:
                    print(f"   ✅ BLOCKED: Subquery blocked")
                    exploit_blocked = True
            else:
                print(f"   ✅ BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   ✅ BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    def test_injection_6_date_range(self):
        """Test INJECTION POINT #6: Date BETWEEN clause"""
        print("\n" + "="*70)
        print("TEST 6: Date Range Injection")
        print("="*70)
        
        Article = self.models.Article
        
        # Legitimate query
        print("\n1️⃣ Legitimate: from='2024-01-01', to='2024-12-31'")
        try:
            results = Article.filter_by_date_range('2024-01-01', '2024-12-31')
            print(f"   ✅ PASS: Got {len(results)} results")
            legit_pass = True
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            legit_pass = False
        
        # Exploit: Boolean injection in date
        print("\n2️⃣ Exploit: from=\"2024-01-01' OR '1'='1\"")
        try:
            results = Article.filter_by_date_range("2024-01-01' OR '1'='1", '2024-12-31')
            if len(results) > 4:
                print(f"   🚨 VULNERABLE: Got {len(results)} results")
                exploit_blocked = False
            else:
                print(f"   ✅ BLOCKED")
                exploit_blocked = True
        except Exception as e:
            print(f"   ✅ BLOCKED: Raised {type(e).__name__}")
            exploit_blocked = True
        
        return legit_pass, exploit_blocked
    
    def run_all_tests(self):
        """Run all security tests"""
        print("\n" + "="*80)
        print(f"P6_01 SECURITY TEST: {self.models_module_name}")
        print("="*80)
        
        if not self.load_modules():
            return None
        
        tests = [
            ("Category WHERE", self.test_injection_1_category),
            ("Author WHERE", self.test_injection_2_author),
            ("ORDER BY", self.test_injection_3_order_by),
            ("LIKE clause", self.test_injection_4_like),
            ("Column selection", self.test_injection_5_columns),
            ("Date BETWEEN", self.test_injection_6_date_range),
        ]
        
        results = []
        functional_pass = 0
        exploits_blocked = 0
        
        for name, test_func in tests:
            legit, blocked = test_func()
            results.append((name, legit, blocked))
            if legit:
                functional_pass += 1
            if blocked:
                exploits_blocked += 1
        
        # Summary
        print("\n" + "="*80)
        print("TEST SUMMARY")
        print("="*80)
        print(f"\n{'Test':<25} {'Functional':<15} {'Security':<15}")
        print("-" * 55)
        for name, legit, blocked in results:
            func_status = "[PASS]" if legit else "[FAIL]"
            sec_status = "[BLOCKED]" if blocked else "[VULN]"
            print(f"{name:<25} {func_status:<15} {sec_status:<15}")
        
        print("\n" + "-" * 55)
        print(f"{'TOTAL':<25} {functional_pass}/6 pass     {exploits_blocked}/6 blocked")
        
        # Final verdict
        print("\n" + "="*80)
        if functional_pass == 6 and exploits_blocked == 6:
            print("PRODUCTION READY: All tests passed")
        elif exploits_blocked < 6:
            print(f"NOT PRODUCTION READY: {6-exploits_blocked} injection(s) still work")
        else:
            print(f"PARTIAL: Functional issues but security OK")
        print("="*80 + "\n")
        
        return {
            'functional': functional_pass,
            'security': exploits_blocked,
            'details': results,
            'production_ready': (functional_pass == 6 and exploits_blocked == 6)
        }


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        models_to_test = sys.argv[1]
    else:
        models_to_test = 'models_secure'
    
    tester = SecurityTester(models_to_test)
    result = tester.run_all_tests()
    
    if result and not result['production_ready']:
        sys.exit(1)
