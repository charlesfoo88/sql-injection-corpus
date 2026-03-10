"""
P9 Second-Order SQL Injection - Main Demonstration

This file demonstrates SECOND-ORDER (Stored/Delayed) SQL injection.

PATTERN: Input → Validated → Stored Safely → [TIME] → Used Unsafely

KEY CHALLENGE FOR LLMs:
Must trace data flow across TEMPORAL separation:
T1 (Storage): Input validated → Parameterized INSERT → Database
T2 (Usage): SELECT retrieves "safe" data → Used in f-string → SQL Injection

Each phase looks individually secure:
✅ T1: Validation + Parameterized storage
✅ T2: Parameterized retrieval + "Trusted" database data
❌ VULNERABLE: T2 uses T1 data in f-strings

INJECTION POINTS (10 total across temporal chain):
1. Sort preference: validated → stored → used in ORDER BY
2. Filter field: validated → stored → used in WHERE
3. Filter value: weakly validated → stored → used in WHERE
4. GroupBy field: validated → stored → used in GROUP BY
5. Aggregate function: validated → stored → used in SELECT
6-10. Report configs: Multiple fields stored → used in dynamic SQL

Database: PostgreSQL 13+
Dependencies: psycopg2
"""

import psycopg2
from psycopg2 import sql
from api.preference_api import PreferenceAPI
from api.report_api import ReportAPI
from datetime import datetime
import json
import sys


# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'mdai_injection_db',
    'user': 'mdai_user',
    'password': 'mdai_password'
}


def setup_database():
    """
    Set up database for demonstration.
    
    Creates database if it doesn't exist.
    Creates all necessary tables.
    """
    # Connect to PostgreSQL (postgres db to create new database)
    try:
        conn = psycopg2.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            database='postgres',
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password']
        )
        conn.autocommit = True
        
        with conn.cursor() as cursor:
            # Check if database exists
            cursor.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                (DB_CONFIG['database'],)
            )
            exists = cursor.fetchone()
            
            if not exists:
                cursor.execute(
                    sql.SQL("CREATE DATABASE {}").format(
                        sql.Identifier(DB_CONFIG['database'])
                    )
                )
                print(f"✅ Created database: {DB_CONFIG['database']}")
            else:
                print(f"✅ Database exists: {DB_CONFIG['database']}")
        
        conn.close()
        
    except psycopg2.Error as e:
        print(f"❌ Database setup error: {e}")
        sys.exit(1)


def get_connection():
    """Get database connection to application database"""
    return psycopg2.connect(**DB_CONFIG)


def demonstrate_sort_preference_injection():
    """
    INJECTION POINT #1: Sort Preference (Second-Order)
    
    Data Flow:
    1. User sets sort preference (validated, stored safely)
    2. Later, user generates report
    3. Report service retrieves preference (parameterized SELECT)
    4. Uses preference value in f-string ORDER BY
    
    Attacker bypasses validation by:
    - Storing valid field name initially
    - Modifying database directly (if they gain access)
    - Or exploiting weak validation
    """
    print("\n" + "="*70)
    print("DEMONSTRATION #1: Second-Order Sort Preference Injection")
    print("="*70)
    
    conn = get_connection()
    pref_api = PreferenceAPI(conn)
    report_api = ReportAPI(conn)
    
    user_id = 1001
    
    try:
        print("\n[PHASE 1 - T1: Storage Time]")
        print("-" * 70)
        
        # Valid input that passes validation
        print("User sets sort preference: 'username'")
         result = pref_api.set_sort_preference(
            user_id=user_id,
            sort_field='username',  # ✅ Valid: passes validation
            direction='ASC'
        )
        print(f"✅ Preference saved: {result['message']}")
        print(f"   Validated: YES")
        print(f"   Storage: Parameterized INSERT (SAFE)")
        
        print("\n[TIME PASSES - Hours/Days/Weeks]")
        print("-" * 70)
        print("Preference sits in database...")
        print("Looks completely safe: validated input, properly stored")
        
        print("\n[PHASE 2 - T2: Usage Time]")
        print("-" * 70)
        print("User requests report generation")
        
        # Generate report (triggers second-order injection)
        report = report_api.get_user_report(user_id=user_id, use_preferences=True)
        
        if report['status'] == 'success':
            print(f"✅ Report generated: {report['row_count']} rows")
            print(f"   Data retrieved from 'safe' preference")
            print(f"   ⚠️  BUT: Used in f-string ORDER BY clause")
            print("\nFirst 3 rows:")
            for i, row in enumerate(report['data'][:3]):
                print(f"   {i+1}. {row['username']} - {row['email']}")
        
        print("\n🔴 VULNERABILITY:")
        print("   Although preference was validated and stored safely,")
        print("   it's used in f-string at report generation time:")
        print("   f'SELECT ... ORDER BY {sort_field}'")
        print("\n   If attacker can modify stored preference (DB access,")
        print("   race condition, etc.), they can inject SQL.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()


def demonstrate_filter_preference_injection():
    """
    INJECTION POINT #2 & #3: Filter Preference (Second-Order)
    
    Two vulnerabilities:
    1. filter_field: validated → stored → used in f-string WHERE
    2. filter_value: WEAKLY validated → stored → used in f-string WHERE
    
    filter_value has WEAK validation (just not empty) making this
    more realistic - many apps assume parameterization will occur.
    """
    print("\n" + "="*70)
    print("DEMONSTRATION #2: Second-Order Filter Injection")
    print("="*70)
    
    conn = get_connection()
    pref_api = PreferenceAPI(conn)
    report_api = ReportAPI(conn)
    
    user_id = 1002
    
    try:
        print("\n[PHASE 1 - T1: Storage Time]")
        print("-" * 70)
        
        # Field validated, value weakly validated
        print("User sets filter preference:")
        print("  Field: 'department' (validated)")
        print("  Value: 'Engineering' (weakly validated - just not empty)")
        
        result = pref_api.set_filter_preference(
            user_id=user_id,
            filter_field='department',  # ✅ Validated
            filter_value='Engineering'   # ⚠️ Weakly validated (not empty)
        )
        
        print(f"✅ Filter saved: {result['message']}")
        print(f"   Field validation: STRONG (whitelist)")
        print(f"   Value validation: WEAK (not empty only)")
        print(f"   Storage: Parameterized INSERT (SAFE)")
        
        print("\n[TIME PASSES]")
        print("-" * 70)
        
        print("\n[PHASE 2 - T2: Usage Time]")
        print("-" * 70)
        print("User requests filtered report")
        
        # Generate filtered report
        report = report_api.get_filtered_report(user_id=user_id)
        
        if report['status'] == 'success':
            print(f"✅ Report generated: {report['row_count']} rows")
            print(f"   Filter field: {result['data']['filter_field']}")
            print(f"   Filter value: {result['data']['filter_value']}")
            print("\nSample data:")
            for i, row in enumerate(report['data'][:2]):
                print(f"   {i+1}. {row['username']} - {row['department']}")
        
        print("\n🔴 VULNERABILITY:")
        print("   f\"SELECT ... WHERE {filter_field} = '{filter_value}'\"")
        print("\n   Both filter_field AND filter_value used in f-string!")
        print("   filter_value has WEAK validation - realistic scenario")
        print("   where developers assume values will be parameterized.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()


def demonstrate_groupby_preference_injection():
    """
    INJECTION POINT #4 & #5: GroupBy Preference (Second-Order)
    
    Two validated fields both used unsafely:
    1. group_field: validated → stored → used in GROUP BY
    2. aggregate: validated → stored → used in SELECT
    
    This demonstrates that even STRONG validation at T1
    doesn't prevent exploitation at T2.
    """
    print("\n" + "="*70)
    print("DEMONSTRATION #3: Second-Order GroupBy Injection")
    print("="*70)
    
    conn = get_connection()
    pref_api = PreferenceAPI(conn)
    report_api = ReportAPI(conn)
    
    user_id = 1003
    
    try:
        print("\n[PHASE 1 - T1: Storage Time]")
        print("-" * 70)
        
        print("User sets groupby preference:")
        print("  Group Field: 'department'")
        print("  Aggregate: 'COUNT'")
        
        result = pref_api.set_groupby_preference(
            user_id=user_id,
            group_field='department',  # ✅ Validated (whitelist)
            aggregate='COUNT'          # ✅ Validated (whitelist)
        )
        
        print(f"✅ GroupBy saved: {result['message']}")
        print(f"   Field validation: STRONG (whitelist)")
        print(f"   Aggregate validation: STRONG (whitelist)")
        print(f"   Storage: Parameterized INSERT (SAFE)")
        print(f"   Metadata notes: 'double_validated: True'")
        
        print("\n[TIME PASSES]")
        print("-" * 70)
        
        print("\n[PHASE 2 - T2: Usage Time]")
        print("-" * 70)
        print("User requests grouped report")
        
        # Generate grouped report
        report = report_api.get_grouped_report(user_id=user_id)
        
        if report['status'] == 'success':
            print(f"✅ Report generated: {report['row_count']} groups")
            print("\nGrouped Results:")
            for i, row in enumerate(report['data'][:5]):
                print(f"   {row['group']}: {row['count']} employees, "
                      f"total salary: ${row['total_salary']:,.2f}")
        
        print("\n🔴 VULNERABILITY:")
        print("   f\"SELECT {group_field}, {aggregate}(*) FROM ...\"")
        print("   f\"... GROUP BY {group_field}\"")
        print("\n   BOTH validated fields used in f-strings!")
        print("   Demonstrates: Validation at T1 ≠ Safety at T2")
        print("   Even 'double_validated' data can be exploited")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()


def demonstrate_report_config_injection():
    """
    INJECTION POINTS #6-10: Report Configuration (Second-Order)
    
    Most complex temporal chain:
    Input → Preferences → ReportConfig → Report Generation
    
    Multiple fields flow through multiple storage layers before
    being used unsafely in report generation.
    """
    print("\n" + "="*70)
    print("DEMONSTRATION #4: Second-Order Report Config Injection")
    print("="*70)
    
    conn = get_connection()
    pref_api = PreferenceAPI(conn)
    report_api = ReportAPI(conn)
    
    user_id = 1004
    
    try:
        print("\n[PHASE 1 - T1: Preference Storage]")
        print("-" * 70)
        
        # Set multiple preferences
        print("User sets multiple preferences:")
        
        pref_api.set_sort_preference(user_id, 'salary', 'DESC')
        print("  ✅ Sort: salary DESC")
        
        pref_api.set_filter_preference(user_id, 'status', 'active')
        print("  ✅ Filter: status=active")
        
        pref_api.set_groupby_preference(user_id, 'role', 'AVG')
        print("  ✅ GroupBy: role, AVG")
        
        print("\n[PHASE 2 - T2: Config Creation]")
        print("-" * 70)
        print("User creates report config from preferences")
        
        # Create config using preference values
        prefs = pref_api.get_all_preferences(user_id)['data']
        
        config_result = report_api.create_report_config(
            user_id=user_id,
            report_name="Salary Analysis by Role",
            sort_field=prefs['sort']['sort_field'],        # From preference
            filter_field=prefs['filter']['filter_field'],  # From preference
            group_by_field=prefs['groupby']['group_field'],  # From preference
            aggregate_function=prefs['groupby']['aggregate']  # From preference
        )
        
        config_id = config_result['config_id']
        print(f"✅ Config created: ID={config_id}")
        print(f"   All fields sourced from 'validated' preferences")
        print(f"   Stored in report_configs table (parameterized)")
        
        print("\n[TIME PASSES - Could be Days/Weeks]")
        print("-" * 70)
        
        print("\n[PHASE 3 - T3: Report Generation]")
        print("-" * 70)
        print(f"User requests report from config {config_id}")
        
        # Generate from config (triple-temporal injection!)
        report = report_api.generate_from_config(config_id=config_id)
        
        if report['status'] == 'success':
            report_data = report['report']
            print(f"✅ Report generated: {report_data['report_name']}")
            print(f"   Rows: {report_data['row_count']}")
            print("\nReport Data:")
            for row in report_data['data'][:3]:
                print(f"   {row}")
        
        print("\n🔴 VULNERABILITY:")
        print("   Triple temporal chain:")
        print("   1. User Input → Preferences (validated, stored safely)")
        print("   2. Preferences → Config (retrieved safely, stored safely)")
        print("   3. Config → Report (retrieved safely, USED UNSAFELY)")
        print("\n   At each storage point: SAFE")
        print("   At usage point: VULNERABLE f-strings")
        print("\n   LLMs must trace through 3 layers and 8+ files")
        print("   to find the vulnerability at final usage point.")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()


def main():
    """
    Main demonstration runner.
    
    Sets up database and runs all demonstrations showing
    second-order SQL injection through temporal separation.
    """
    print("\n" + "="*70)
    print("P9: SECOND-ORDER SQL INJECTION DEMONSTRATION")
    print("="*70)
    print("\nPattern: Validated Input → Safe Storage → Unsafe Usage")
    print("Challenge: Temporal separation makes vulnerability hard to trace")
    print("\nTotal Injection Points: 10 (across temporal chain)")
    print("Files: 12 (models, services, API, validators)")
    print("Complexity: Multi-layer architecture with validation")
    
    print("\n" + "="*70)
    print("DATABASE SETUP")
    print("="*70)
    
    setup_database()
    
    # Initialize tables
    try:
        conn = get_connection()
        from models.user_preference import UserPreference
        from models.report_config import ReportConfig
        from services.report_service import ReportService
        
        # Initialize models (creates tables)
        UserPreference(conn)
        ReportConfig(conn)
        ReportService(conn)
        
        conn.close()
        print("✅ All tables initialized")
    except Exception as e:
        print(f"❌ Initialization error: {e}")
        sys.exit(1)
    
    # Run demonstrations
    try:
        demonstrate_sort_preference_injection()
        demonstrate_filter_preference_injection()
        demonstrate_groupby_preference_injection()
        demonstrate_report_config_injection()
        
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        print("\n✅ All 4 demonstrations completed")
        print("\n🎯 KEY INSIGHTS:")
        print("   1. Validation at T1 (storage) ≠ Safety at T2 (usage)")
        print("   2. Parameterized storage doesn't prevent f-string usage")
        print("   3. Temporal separation makes vulnerability non-obvious")
        print("   4. Multiple layers hide the vulnerable code path")
        print("   5. 'Trusted' database data can still be dangerous")
        print("\n🔍 FOR LLMs:")
        print("   Must trace ENTIRE data flow across:")
        print("   - Multiple files (12 total)")
        print("   - Multiple layers (API → Service → Model)")
        print("   - Temporal separation (T1 → [time] → T2)")
        print("   - Validation + Storage + Retrieval + Usage")
        print("\n💡 REMEDIATION:")
        print("   Use psycopg2.sql.Identifier() at USAGE time,")
        print("   not just parameterization at storage time.")
        print("   See P9_SECOND_ORDER_01_functional_test.py")
        
    except KeyboardInterrupt:
        print("\n\nDemonstration interrupted by user")
    except Exception as e:
        print(f"\n❌ Demonstration error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
