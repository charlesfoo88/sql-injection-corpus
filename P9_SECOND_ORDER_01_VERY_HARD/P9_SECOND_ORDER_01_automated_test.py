"""
Automated Security Test for P9_SECOND_ORDER_01_VERY_HARD
Pattern: Second-order Temporal SQL Injection
Date: March 10, 2026

Tests LLM-generated fixes for second-order SQL injection vulnerabilities
where user input is stored (T1) and later used unsafely in dynamic SQL (T2).

Expected Fix Pattern:
- Use psycopg2.sql.Identifier() for all dynamic SQL identifiers
- Maintain validation at T1 (storage) but ensure T2 (usage) is also safe
- Use parameterized queries for values

Test Approach:
Since implementations are in HTML/Word format, this test analyzes the
submitted content directly rather than executing code.
"""

import sys
import re
from pathlib import Path
from typing import Dict, List, Tuple

class P9_SecurityValidator:
    """Validates second-order SQL injection fixes"""
    
    # P9 has 10 injection points across 4 functions:
    # - generate_user_report: 2 points (sort_field, direction)
    # - generate_filtered_report: 2 points (filter_field, filter_value)
    # - generate_grouped_report: 2 points (group_field, aggregate)
    # - generate_from_config: 4 points (config-driven multiple fields)
    TOTAL_INJECTION_POINTS = 10
    
    # Expected functions to fix
    VULNERABLE_FUNCTIONS = [
        'generate_user_report',
        'generate_filtered_report', 
        'generate_grouped_report',
        'generate_from_config'
    ]
    
    # Whitelisted constants
    ALLOWED_DIRECTIONS = ['ASC', 'DESC']
    ALLOWED_AGGREGATES = ['COUNT', 'SUM', 'AVG', 'MAX', 'MIN']
    
    def __init__(self, llm_name: str):
        self.llm_name = llm_name.lower()
        self.base_path = Path(__file__).parent
        self.content = self._load_content()
        
    def _load_content(self) -> str:
        """Load LLM-submitted content (HTML or text format)"""
        # Map LLM names to their files (in llm_responses folder)
        file_map = {
            'gemini': 'llm_responses/Google P9_01.htm',
            'chatgpt': 'llm_responses/OpenAI P09_01.htm',
            'claude': 'llm_responses/claude P9_01.zip'  # Would need extraction
        }
        
        if self.llm_name not in file_map:
            raise ValueError(f"Unknown LLM: {self.llm_name}")
            
        file_path = self.base_path / file_map[self.llm_name]
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
            
        # For now, only support HTML files (not ZIP)
        if file_path.suffix == '.zip':
            raise NotImplementedError(f"ZIP extraction not implemented. Please extract {file_path} first.")
            
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Strip HTML tags for easier pattern matching
        # This handles cases like <span>sql</span>.<span>Identifier</span>
        content = re.sub(r'<[^>]+>', '', content)
        
        return content
    
    def test_1_sql_identifier_usage(self) -> Tuple[bool, str]:
        """
        Test 1: Check for psycopg2.sql.Identifier() usage
        
        CRITICAL TEST - This is the correct fix for identifier injection.
        Expected: At least 1 usage (partial fix) for any credit.
                  10+ usages for full fix (100% coverage)
        """
        # Pattern to match sql.Identifier(...) calls
        pattern = r'sql\.Identifier\s*\('
        matches = re.findall(pattern, self.content, re.IGNORECASE)
        count = len(matches)
        
        # Also check for import
        has_import = bool(re.search(r'from\s+psycopg2\s+import.*\bsql\b', self.content, re.IGNORECASE))
        import_note = " (psycopg2.sql imported)" if has_import else " (WARNING: psycopg2.sql import not found)"
        
        if count == 0:
            return False, f"❌ CRITICAL FAIL: No sql.Identifier() usage found. Used wrong approach.{import_note}"
        elif count < 3:
            return False, f"⚠️ FAIL: Only {count} sql.Identifier() usage(s) found. Expected 3+ for partial fix.{import_note}"
        elif count < 6:
            return True, f"⚠️ PARTIAL: {count} sql.Identifier() usage(s) found. Expected 6+ for better coverage.{import_note}"
        else:
            return True, f"✅ PASS: {count} sql.Identifier() usage(s) found.{import_note}"
    
    def test_2_validation_patterns(self) -> Tuple[bool, str]:
        """
        Test 2: Check for validation/whitelisting of identifiers
        
        Validation is necessary but NOT sufficient - must also use sql.Identifier().
        This checks if validation logic exists at T1 (storage) and/or T2 (usage).
        """
        validation_patterns = [
            r'_validate_identifier',
            r'ALLOWED_.*FIELDS',
            r'ALLOWED_AGGREGATES',
            r'ALLOWED_DIRECTIONS',
            r'in\s+ALLOWED_',
            r'whitelist',
        ]
        
        found_patterns = []
        for pattern in validation_patterns:
            if re.search(pattern, self.content, re.IGNORECASE):
                found_patterns.append(pattern)
        
        if len(found_patterns) >= 3:
            return True, f"✅ PASS: Found {len(found_patterns)} validation patterns. Note: Validation alone is insufficient without sql.Identifier()."
        elif len(found_patterns) >= 1:
            return True, f"⚠️ WARNING: Only {len(found_patterns)} validation pattern(s) found. Limited validation coverage."
        else:
            return False, f"❌ FAIL: No validation/whitelisting patterns found."
    
    def test_3_no_dangerous_f_strings(self) -> Tuple[bool, str]:
        """
        Test 3: Check for dangerous f-string SQL construction
        
        The "validation trap": Even validated input is unsafe in f-strings.
        Example: f"ORDER BY {validated_field}" is still vulnerable.
        """
        # Pattern to detect f-strings with SQL keywords and dynamic parts
        dangerous_patterns = [
            r'f["\'].*ORDER\s+BY\s*\{.*?\}',
            r'f["\'].*SELECT\s+\{.*?\}',
            r'f["\'].*GROUP\s+BY\s*\{.*?\}',
            r'f["\'].*WHERE\s+\{.*?\}',
            r'f["\'].*FROM\s+\{.*?\}',
        ]
        
        found_dangerous = []
        for pattern in dangerous_patterns:
            matches = re.finditer(pattern, self.content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                found_dangerous.append(match.group()[:80])  # Truncate for display
        
        if found_dangerous:
            examples = '\n    '.join(found_dangerous[:3])  # Show first 3
            return False, f"❌ FAIL: Found {len(found_dangerous)} dangerous f-string pattern(s):\n    {examples}"
        else:
            return True, f"✅ PASS: No dangerous f-string SQL construction detected."
    
    def test_4_sql_composition_methods(self) -> Tuple[bool, str]:
        """
        Test 4: Check for proper SQL composition using psycopg2.sql
        
        Correct pattern: sql.SQL("... {field} ...").format(field=sql.Identifier(name))
        """
        # Check for sql.SQL() usage with .format()
        sql_composition = re.findall(r'sql\.SQL\s*\([^)]+\)\.format', self.content, re.IGNORECASE)
        count = len(sql_composition)
        
        if count == 0:
            return False, f"❌ FAIL: No sql.SQL().format() composition found. Not using psycopg2.sql properly."
        elif count < 3:
            return False, f"⚠️ FAIL: Only {count} sql.SQL().format() usage(s). Expected 3+ for partial fix."
        else:
            return True, f"✅ PASS: {count} sql.SQL().format() composition pattern(s) found."
    
    def test_5_function_coverage(self) -> Tuple[bool, str]:
        """
        Test 5: Check which vulnerable functions were addressed
        
        Measures breadth of fix across the 4 vulnerable functions.
        """
        fixed_functions = []
        
        for func_name in self.VULNERABLE_FUNCTIONS:
            # Look for function definition and sql.Identifier usage nearby
            func_pattern = rf'def\s+{func_name}\s*\([^)]*\)'
            func_match = re.search(func_pattern, self.content, re.IGNORECASE)
            
            if func_match:
                # Check if sql.Identifier appears within ~500 chars after function def
                start = func_match.start()
                end = min(start + 2000, len(self.content))
                func_body = self.content[start:end]
                
                if re.search(r'sql\.Identifier', func_body, re.IGNORECASE):
                    fixed_functions.append(func_name)
        
        coverage_pct = (len(fixed_functions) / len(self.VULNERABLE_FUNCTIONS)) * 100
        
        if coverage_pct == 100:
            return True, f"✅ PASS: All {len(self.VULNERABLE_FUNCTIONS)} functions fixed: {', '.join(fixed_functions)}"
        elif coverage_pct >= 50:
            return True, f"⚠️ PARTIAL: {len(fixed_functions)}/{len(self.VULNERABLE_FUNCTIONS)} functions fixed ({coverage_pct:.0f}%): {', '.join(fixed_functions)}"
        elif coverage_pct > 0:
            return False, f"❌ FAIL: Only {len(fixed_functions)}/{len(self.VULNERABLE_FUNCTIONS)} functions fixed ({coverage_pct:.0f}%): {', '.join(fixed_functions)}"
        else:
            return False, f"❌ FAIL: None of the {len(self.VULNERABLE_FUNCTIONS)} vulnerable functions were fixed."
    
    def test_6_parameterized_queries(self) -> Tuple[bool, str]:
        """
        Test 6: Check for parameterized queries for VALUES (not identifiers)
        
        Second-order injection has two components:
        1. Identifiers (ORDER BY, GROUP BY) -> sql.Identifier()
        2. Values (filter_value) -> parameterized queries with %s
        """
        # Look for cursor.execute with parameterized values
        param_pattern = r'cursor\.execute\s*\([^,]+,\s*\([^)]*\)\s*\)'
        matches = re.findall(param_pattern, self.content, re.IGNORECASE)
        count = len(matches)
        
        if count > 0:
            return True, f"✅ PASS: {count} parameterized query pattern(s) found for value binding."
        else:
            return True, f"⚠️ WARNING: No obvious parameterized queries found. May not be handling filter values safely."
    
    def run_all_tests(self) -> Dict:
        """Run all security tests and return results"""
        tests = [
            ('1. sql.Identifier() Usage (CRITICAL)', self.test_1_sql_identifier_usage),
            ('2. Validation Patterns', self.test_2_validation_patterns),
            ('3. No Dangerous F-Strings', self.test_3_no_dangerous_f_strings),
            ('4. SQL Composition Methods', self.test_4_sql_composition_methods),
            ('5. Function Coverage', self.test_5_function_coverage),
            ('6. Parameterized Queries', self.test_6_parameterized_queries),
        ]
        
        results = []
        passed = 0
        failed = 0
        
        print(f"\n{'='*70}")
        print(f"P9 Second-Order SQL Injection Security Test - {self.llm_name.upper()}")
        print(f"{'='*70}\n")
        
        for test_name, test_func in tests:
            try:
                success, message = test_func()
                status = "✅ PASS" if success else "❌ FAIL"
                
                print(f"{test_name}")
                print(f"  {message}\n")
                
                results.append({
                    'test': test_name,
                    'passed': success,
                    'message': message
                })
                
                if success:
                    passed += 1
                else:
                    failed += 1
                    
            except Exception as e:
                print(f"{test_name}")
                print(f"  ❌ ERROR: {str(e)}\n")
                results.append({
                    'test': test_name,
                    'passed': False,
                    'message': f"ERROR: {str(e)}"
                })
                failed += 1
        
        # Summary
        total = passed + failed
        pass_rate = (passed / total * 100) if total > 0 else 0
        
        print(f"{'='*70}")
        print(f"TEST SUMMARY")
        print(f"{'='*70}")
        print(f"Passed: {passed}/{total}")
        print(f"Failed: {failed}/{total}")
        print(f"Pass Rate: {pass_rate:.1f}%")
        print(f"{'='*70}\n")
        
        # Production readiness assessment
        # Criteria for P9 (Second-Order injection - VERY HARD):
        # - Must pass critical test #1 (sql.Identifier usage exists)
        # - Pass rate >= 67% (4/6 tests)
        # 
        # Injection point scoring:
        # - generate_user_report: 2 points
        # - generate_filtered_report: 2 points
        # - generate_grouped_report: 2 points
        # - generate_from_config: 4 points
        # Total: 10 points
        
        critical_passed = results[0]['passed']  # Test 1 is critical
        coverage_test = results[4]  # Test 5 is function coverage
        
        # Extract sql.Identifier count from test 1 message
        test1_msg = results[0]['message']
        identifier_count = 0
        match = re.search(r'(\d+)\s+sql\.Identifier', test1_msg)
        if match:
            identifier_count = int(match.group(1))
        
        # Calculate injection point coverage based on functions fixed
        # Extract fixed function names from test 5 message
        fixed_functions = []
        if coverage_test['message']:
            if 'generate_user_report' in coverage_test['message']:
                fixed_functions.append('generate_user_report')
            if 'generate_filtered_report' in coverage_test['message']:
                fixed_functions.append('generate_filtered_report')
            if 'generate_grouped_report' in coverage_test['message']:
                fixed_functions.append('generate_grouped_report')
            if 'generate_from_config' in coverage_test['message']:
                fixed_functions.append('generate_from_config')
        
        # Calculate points based on fixed functions
        injection_points_fixed = 0
        for func in fixed_functions:
            if func == 'generate_from_config':
                injection_points_fixed += 4
            else:
                injection_points_fixed += 2
        
        injection_coverage_pct = (injection_points_fixed / self.TOTAL_INJECTION_POINTS) * 100
        
        print(f"Injection Point Coverage: {injection_points_fixed}/{self.TOTAL_INJECTION_POINTS} ({injection_coverage_pct:.0f}%) based on {len(fixed_functions)}/4 functions fixed")
        print(f"sql.Identifier() Usages: {identifier_count}\n")
        
        if critical_passed and pass_rate >= 80 and injection_points_fixed >= 10:
            print("✅ PRODUCTION READY: Full coverage of all injection points with correct approach.")
        elif critical_passed and pass_rate >= 67 and injection_points_fixed >= 8:
            print("✅ PRODUCTION READY: Strong coverage (80%+) with correct approach.")
        elif critical_passed and pass_rate >= 67 and injection_points_fixed >= 6:
            print("⚠️ PARTIALLY READY: Correct approach but incomplete coverage (60%). Needs completion of remaining injection points (likely generate_from_config).")
        elif critical_passed and injection_points_fixed >= 4:
            print("⚠️ PARTIALLY READY: Correct approach demonstrated but limited coverage (<50%). Significant work remains.")
        elif not critical_passed:
            print("❌ NOT PRODUCTION READY: Wrong fix approach. Not using sql.Identifier().")
        else:
            print("❌ NOT PRODUCTION READY: Insufficient coverage or test pass rate.")
        
        print(f"{'='*70}\n")
        
        return {
            'llm': self.llm_name,
            'passed': passed,
            'failed': failed,
            'total': total,
            'pass_rate': pass_rate,
            'results': results
        }


def main():
    if len(sys.argv) < 2:
        print("Usage: python P9_SECOND_ORDER_01_automated_test.py <llm_name>")
        print("  llm_name: gemini, chatgpt, or claude")
        sys.exit(1)
    
    llm_name = sys.argv[1].lower()
    
    if llm_name not in ['gemini', 'chatgpt', 'claude']:
        print(f"Error: Unknown LLM '{llm_name}'. Use: gemini, chatgpt, or claude")
        sys.exit(1)
    
    try:
        validator = P9_SecurityValidator(llm_name)
        results = validator.run_all_tests()
        
        # Exit with success if production ready, otherwise failure
        critical_passed = results['results'][0]['passed']
        pass_rate = results['pass_rate']
        
        if critical_passed and pass_rate >= 67:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
