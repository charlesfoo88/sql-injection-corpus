"""
P9 Second-Order SQL Injection - Runtime Test Runner

Tests LLM implementations with actual PostgreSQL database execution.
Similar to P5/P6 test methodology.

Usage: python run_runtime_tests.py [claude|chatgpt|gemini|all]
"""

import sys
import os
import importlib.util
import psycopg2
from pathlib import Path
from typing import Dict, List, Any

class P9RuntimeTester:
    """Runtime testing for P9 second-order SQL injection fixes"""
    
    def __init__(self, llm_name: str):
        self.llm_name = llm_name.lower()
        self.db_config = {
            'host': 'localhost',
            'port': 5432,
            'database': f'testdb_p9_{llm_name}',
            'user': 'postgres',
            'password': 'postgres123'
        }
        self.results = {
            'functional_passed': 0,
            'functional_total': 0,
            'exploit_blocked': 0,
            'exploit_total': 0,
            'errors': []
        }
    
    def setup_database(self):
        """Create test database and tables"""
        try:
            # Connect to default database
            default_config = self.db_config.copy()
            default_config['database'] = 'postgres'
            conn = psycopg2.connect(**default_config)
            conn.autocommit = True
            cursor = conn.cursor()
            
            # Recreate test database
            db_name = self.db_config['database']
            cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
            cursor.execute(f"CREATE DATABASE {db_name}")
            cursor.close()
            conn.close()
            
            # Connect to new database
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            
            # Create employees table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS employees (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    email VARCHAR(200),
                    department VARCHAR(100),
                    role VARCHAR(100),
                    salary INTEGER,
                    age INTEGER,
                    hire_date DATE
                )
            """)
            
            # Create user_preferences table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_preferences (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    preference_key VARCHAR(100) NOT NULL,
                    preference_value TEXT
                )
            """)
            
            # Create report_configs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS report_configs (
                    id SERIAL PRIMARY KEY,
                    config_name VARCHAR(100) NOT NULL,
                    sort_field VARCHAR(100),
                    filter_field VARCHAR(100),
                    filter_value VARCHAR(100),
                    group_by_field VARCHAR(100),
                    aggregate_function VARCHAR(50)
                )
            """)
            
            # Insert test data
            cursor.execute("""
                INSERT INTO employees (username, email, department, role, salary, age, hire_date)
                VALUES 
                    ('alice', 'alice@company.com', 'Engineering', 'Developer', 80000, 28, '2022-01-15'),
                    ('bob', 'bob@company.com', 'Sales', 'Manager', 90000, 35, '2020-05-20'),
                    ('charlie', 'charlie@company.com', 'Engineering', 'Senior Dev', 100000, 32, '2019-03-10'),
                    ('diana', 'diana@company.com', 'HR', 'Recruiter', 70000, 29, '2021-08-01')
            """)
            
            conn.commit()
            cursor.close()
            conn.close()
            
            print(f"✓ Database setup complete: {db_name}")
            return True
            
        except Exception as e:
            print(f"✗ Database setup failed: {e}")
            self.results['errors'].append(f"Database setup: {e}")
            return False
    
    def load_implementation(self):
        """Load LLM implementation"""
        try:
            impl_path = Path(__file__).parent / 'llm_extracted' / f'{self.llm_name}_extracted'
            
            if self.llm_name == 'claude':
                # Load Claude's report_service_secure.py
                service_file = impl_path / 'report_service_secure.py'
                if not service_file.exists():
                    raise FileNotFoundError(f"Claude implementation not found: {service_file}")
                
                spec = importlib.util.spec_from_file_location("report_service", service_file)
                module = importlib.util.module_from_spec(spec)
                sys.modules['report_service'] = module
                spec.loader.exec_module(module)
                
                return module.ReportService
            
            else:
                raise NotImplementedError(f"Implementation loading for {self.llm_name} not yet implemented")
                
        except Exception as e:
            print(f"✗ Failed to load {self.llm_name} implementation: {e}")
            self.results['errors'].append(f"Load implementation: {e}")
            return None
    
    def run_functional_tests(self, ReportService):
        """Run functional tests - verify code works correctly"""
        print(f"\n{'='*60}")
        print(f"FUNCTIONAL TESTS - {self.llm_name.upper()}")
        print(f"{'='*60}\n")
        
        try:
            conn = psycopg2.connect(**self.db_config)
            service = ReportService(conn)
            
            # Test 1: generate_user_report
            print("Test 1: generate_user_report()")
            self.results['functional_total'] += 1
            try:
                result = service.generate_user_report(user_id=1)
                if result and len(result) > 0:
                    print("  ✓ PASS - Returns results")
                    self.results['functional_passed'] += 1
                else:
                    print("  ✗ FAIL - No results returned")
            except Exception as e:
                print(f"  ✗ FAIL - {e}")
                self.results['errors'].append(f"Functional test 1: {e}")
            
            conn.close()
            
        except Exception as e:
            print(f"✗ Functional tests failed: {e}")
            self.results['errors'].append(f"Functional tests setup: {e}")
    
    def run_exploit_tests(self, ReportService):
        """Run exploit tests - verify injections are blocked"""
        print(f"\n{'='*60}")
        print(f"EXPLOIT TESTS - {self.llm_name.upper()}")
        print(f"{'='*60}\n")
        
        # Implement exploit tests here
        print("Exploit tests not yet implemented")
    
    def save_results(self):
        """Save test results to file"""
        output_dir = Path(__file__).parent / 'test_outputs'
        output_dir.mkdir(exist_ok=True)
        
        output_file = output_dir / f'test_runtime_{self.llm_name}.txt'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"P9 Runtime Test Results - {self.llm_name.upper()}\n")
            f.write("="*60 + "\n\n")
            f.write(f"Functional Tests: {self.results['functional_passed']}/{self.results['functional_total']}\n")
            f.write(f"Exploit Tests: {self.results['exploit_blocked']}/{self.results['exploit_total']}\n\n")
            
            if self.results['errors']:
                f.write("Errors:\n")
                for err in self.results['errors']:
                    f.write(f"  - {err}\n")
        
        print(f"\n✓ Results saved to: {output_file}")
    
    def run_all_tests(self):
        """Run complete test suite"""
        print(f"\n{'='*70}")
        print(f"P9 RUNTIME TESTING - {self.llm_name.upper()}")
        print(f"{'='*70}\n")
        
        if not self.setup_database():
            return False
        
        ReportService = self.load_implementation()
        if not ReportService:
            return False
        
        self.run_functional_tests(ReportService)
        self.run_exploit_tests(ReportService)
        self.save_results()
        
        return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python run_runtime_tests.py [claude|chatgpt|gemini|all]")
        sys.exit(1)
    
    llm_name = sys.argv[1].lower()
    
    if llm_name == 'all':
        for llm in ['claude', 'chatgpt', 'gemini']:
            tester = P9RuntimeTester(llm)
            tester.run_all_tests()
    else:
        tester = P9RuntimeTester(llm_name)
        tester.run_all_tests()

if __name__ == '__main__':
    main()
