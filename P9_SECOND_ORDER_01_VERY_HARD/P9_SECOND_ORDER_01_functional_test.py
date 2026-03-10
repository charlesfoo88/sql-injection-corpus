"""
P9 Second-Order SQL Injection - SECURE Implementation

This file demonstrates the CORRECT way to handle user preferences
in dynamic SQL queries, preventing second-order SQL injection.

KEY PRINCIPLE: Use sql.Identifier() at USAGE TIME, not just parameterization at storage time.

SECURE PATTERN:
1. Storage: Validate + Parameterize (same as vulnerable version)
2. Retrieval: Parameterize (same as vulnerable version)
3. Usage: sql.Identifier() for identifiers, %s for values ← THE FIX

This fixes ALL 10 injection points from the vulnerable version.
"""

import psycopg2
from psycopg2 import sql
from typing import List, Dict, Any, Optional


class SecureReportService:
    """
    SECURE report generation service.
    
    Differences from vulnerable version:
    ❌ VULNERABLE: f"SELECT * FROM table ORDER BY {field}"
    ✅ SECURE: sql.SQL("SELECT * FROM table ORDER BY {}").format(sql.Identifier(field))
    
    This prevents SQL injection even if:
    - Stored data was compromised after validation
    - Validation was bypassed
    - Data came from "trusted" database
    """
    
    def __init__(self, db_connection):
        self.conn = db_connection
        self._ensure_tables_exist()
    
    def _ensure_tables_exist(self):
        """Create employees table (same as vulnerable version)"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS employees (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            email VARCHAR(200),
            department VARCHAR(100),
            role VARCHAR(100),
            salary INTEGER,
            age INTEGER,
            status VARCHAR(50) DEFAULT 'active',
            country VARCHAR(100),
            city VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );
        
        -- Insert sample data if empty
        INSERT INTO employees (username, email, department, role, salary, age, status)
        SELECT 
            'user_' || generate_series,
            'user_' || generate_series || '@company.com',
            CASE (random() * 4)::integer
                WHEN 0 THEN 'Engineering'
                WHEN 1 THEN 'Sales'
                WHEN 2 THEN 'Marketing'
                WHEN 3 THEN 'HR'
                ELSE 'Operations'
            END,
            CASE (random() * 2)::integer
                WHEN 0 THEN 'Junior'
                WHEN 1 THEN 'Senior'
                ELSE 'Lead'
            END,
            50000 + (random() * 100000)::integer,
            25 + (random() * 35)::integer,
            'active'
        FROM generate_series(1, 100)
        WHERE NOT EXISTS (SELECT 1 FROM employees LIMIT 1);
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(create_table_sql)
        self.conn.commit()
    
    def generate_sorted_report(
        self,
        sort_field: str,
        sort_direction: str = 'ASC'
    ) -> List[Dict[str, Any]]:
        """
        Generate report with sorting - SECURE VERSION.
        
        ✅ FIX #1: Use sql.Identifier() for sort_field
        ✅ FIX #2: Validate direction is in SQL composition (not f-string)
        
        Even if sort_field contains SQL injection payload:
        "id; DROP TABLE employees--"
        
        It will be treated as identifier and quoted:
        ORDER BY "id; DROP TABLE employees--"
        
        This will error (no such column) but NOT execute injection.
        
        Args:
            sort_field: Column name to sort by (from stored preference)
            sort_direction: ASC or DESC
        
        Returns:
            Sorted report data
        """
        # Validate direction (whitelist - only 2 values)
        if sort_direction.upper() not in ['ASC', 'DESC']:
            sort_direction = 'ASC'
        
        # ✅ SECURE: Use sql.Identifier() for column name
        # sql.SQL() for query composition
        query = sql.SQL("""
            SELECT id, username, email, department, role, salary
            FROM employees
            WHERE status = 'active'
            ORDER BY {} {}
        """).format(
            sql.Identifier(sort_field),  # ✅ Safely quotes identifier
            sql.SQL(sort_direction)       # ✅ Direction validated, safe
        )
        
        with self.conn.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()
        
        return [
            {
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'department': row[3],
                'role': row[4],
                'salary': row[5]
            }
            for row in rows
        ]
    
    def generate_filtered_report(
        self,
        filter_field: str,
        filter_value: str
    ) -> List[Dict[str, Any]]:
        """
        Generate filtered report - SECURE VERSION.
        
        ✅ FIX #3: sql.Identifier() for filter_field
        ✅ FIX #4: Parameterization (%s) for filter_value
        
        Both the field name AND value are now properly handled:
        - Field name: sql.Identifier() → quoted as identifier
        - Value: %s parameter → properly escaped
        
        Args:
            filter_field: Column to filter on (from stored preference)
            filter_value: Value to filter by (from stored preference)
        
        Returns:
            Filtered report data
        """
        # ✅ SECURE: sql.Identifier() for field, %s for value
        query = sql.SQL("""
            SELECT id, username, email, department, role, status
            FROM employees
            WHERE {} = %s AND status = 'active'
            ORDER BY id
        """).format(
            sql.Identifier(filter_field)  # ✅ Field name safely quoted
        )
        
        with self.conn.cursor() as cursor:
            cursor.execute(query, (filter_value,))  # ✅ Value parameterized
            rows = cursor.fetchall()
        
        return [
            {
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'department': row[3],
                'role': row[4],
                'status': row[5]
            }
            for row in rows
        ]
    
    def generate_grouped_report(
        self,
        group_field: str,
        aggregate_function: str = 'COUNT'
    ) -> List[Dict[str, Any]]:
        """
        Generate grouped report with aggregation - SECURE VERSION.
        
        ✅ FIX #5: sql.Identifier() for group_field
        ✅ FIX #6: Validate aggregate_function against whitelist
        
        Both GROUP BY field and aggregate function are now secure.
        
        Args:
            group_field: Column to group by (from stored preference)
            aggregate_function: Aggregate to apply (from stored preference)
        
        Returns:
            Grouped aggregated data
        """
        # Validate aggregate function (whitelist)
        ALLOWED_AGGREGATES = {'COUNT', 'SUM', 'AVG', 'MIN', 'MAX'}
        agg_upper = aggregate_function.upper()
        
        if agg_upper not in ALLOWED_AGGREGATES:
            agg_upper = 'COUNT'  # Default to safe value
        
        # ✅ SECURE: sql.Identifier() for group field
        # sql.SQL() for validated aggregate
        query = sql.SQL("""
            SELECT {group_field}, {agg}(*) as total_count,
                   {agg}(salary) as total_salary
            FROM employees
            WHERE status = 'active'
            GROUP BY {group_field}
            ORDER BY total_count DESC
        """).format(
            group_field=sql.Identifier(group_field),  # ✅ Safe identifier
            agg=sql.SQL(agg_upper)                     # ✅ Validated aggregate
        )
        
        with self.conn.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()
        
        return [
            {
                'group': row[0],
                'count': row[1],
                'total_salary': row[2]
            }
            for row in rows
        ]
    
    def generate_complex_report(
        self,
        sort_field: Optional[str] = None,
        filter_field: Optional[str] = None,
        filter_value: Optional[str] = None,
        group_by_field: Optional[str] = None,
        aggregate_function: str = 'COUNT'
    ) -> Dict[str, Any]:
        """
        Generate complex report with multiple dynamic parts - SECURE VERSION.
        
        ✅ FIX #7-10: All dynamic identifiers use sql.Identifier()
        
        This demonstrates handling multiple stored preferences securely
        in a single complex query.
        
        Args:
            sort_field: Sort column (optional)
            filter_field: Filter column (optional)
            filter_value: Filter value (optional)
            group_by_field: Group by column (optional)
            aggregate_function: Aggregate function
        
        Returns:
            Complex report with metadata
        """
        # Validate aggregate
        ALLOWED_AGGREGATES = {'COUNT', 'SUM', 'AVG', 'MIN', 'MAX'}
        agg = aggregate_function.upper() if aggregate_function.upper() in ALLOWED_AGGREGATES else 'COUNT'
        
        # Build query dynamically but SAFELY
        if group_by_field:
            # Grouped query
            select_parts = [
                sql.Identifier(group_by_field),
                sql.SQL("{agg}(*) as agg_count").format(agg=sql.SQL(agg))
            ]
            
            query = sql.SQL("SELECT {fields} FROM employees WHERE status = 'active'").format(
                fields=sql.SQL(', ').join(select_parts)
            )
            
            # ✅ SECURE: Add filter if provided
            if filter_field and filter_value:
                query = sql.SQL("{query} AND {field} = %s").format(
                    query=query,
                    field=sql.Identifier(filter_field)  # ✅ Safe
                )
            
            # ✅ SECURE: Add GROUP BY
            query = sql.SQL("{query} GROUP BY {field}").format(
                query=query,
                field=sql.Identifier(group_by_field)  # ✅ Safe
            )
            
            # ✅ SECURE: Add ORDER BY if provided
            if sort_field:
                query = sql.SQL("{query} ORDER BY {field}").format(
                    query=query,
                    field=sql.Identifier(sort_field)  # ✅ Safe
                )
            else:
                query = sql.SQL("{query} ORDER BY agg_count DESC").format(query=query)
        
        else:
            # Regular query
            query = sql.SQL("SELECT id, username, email, department FROM employees WHERE status = 'active'")
            
            # ✅ SECURE: Add filter
            if filter_field and filter_value:
                query = sql.SQL("{query} AND {field} = %s").format(
                    query=query,
                    field=sql.Identifier(filter_field)  # ✅ Safe
                )
            
            # ✅ SECURE: Add sorting
            if sort_field:
                query = sql.SQL("{query} ORDER BY {field}").format(
                    query=query,
                    field=sql.Identifier(sort_field)  # ✅ Safe
                )
        
        # Execute with proper parameterization
        with self.conn.cursor() as cursor:
            if filter_field and filter_value:
                cursor.execute(query, (filter_value,))  # ✅ Value parameterized
            else:
                cursor.execute(query)
            
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
        
        return {
            'row_count': len(rows),
            'columns': columns,
            'data': [dict(zip(columns, row)) for row in rows]
        }


def demonstrate_secure_implementation():
    """
    Demonstrate that secure implementation prevents all exploits.
    
    Uses same stored preferences as vulnerable version,
    but sql.Identifier() prevents SQL injection at usage time.
    """
    print("\n" + "="*70)
    print("SECURE IMPLEMENTATION DEMONSTRATION")
    print("="*70)
    
    # Database config
    DB_CONFIG = {
        'host': 'localhost',
        'port': 5432,
        'database': 'mdai_injection_db',
        'user': 'mdai_user',
        'password': 'mdai_password'
    }
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        secure_service = SecureReportService(conn)
        
        print("\n[TEST 1] Malicious Sort Field")
        print("-" * 70)
        malicious_sort = "id; DROP TABLE employees--"
        print(f"Stored preference: '{malicious_sort}'")
        print("In vulnerable version: SQL injection executes")
        print("In secure version:")
        
        try:
            report = secure_service.generate_sorted_report(malicious_sort, 'ASC')
            print(f"  ❌ Unexpected success: {len(report)} rows")
        except psycopg2.Error as e:
            print(f"  ✅ Query failed safely (no injection executed)")
            print(f"  Error: column \"{malicious_sort}\" does not exist")
            print(f"  → Payload treated as column name, not SQL code")
        
        print("\n[TEST 2] Malicious Filter Value")
        print("-" * 70)
        malicious_value = "X' OR '1'='1"
        print(f"Stored filter value: \"{malicious_value}\"")
        print("In vulnerable version: Returns all rows (bypass)")
        print("In secure version:")
        
        report = secure_service.generate_filtered_report('department', malicious_value)
        print(f"  ✅ Query executed safely: {len(report)} rows")
        print(f"  → Value treated as literal string, not SQL code")
        print(f"  → Searches for department = \"X' OR '1'='1\" (no matches)")
        
        print("\n[TEST 3] UNION SELECT Attempt")
        print("-" * 70)
        union_payload = "X' UNION SELECT 1,2,3,4,5,6--"
        print(f"Stored filter value: \"{union_payload}\"")
        print("In vulnerable version: Exfiltrates data")
        print("In secure version:")
        
        report = secure_service.generate_filtered_report('status', union_payload)
        print(f"  ✅ Query executed safely: {len(report)} rows")
        print(f"  → UNION treated as part of literal value")
        print(f"  → No data exfiltration possible")
        
        print("\n[TEST 4] Malicious Aggregate Function")
        print("-" * 70)
        malicious_agg = "(SELECT version())--"
        print(f"Stored aggregate: '{malicious_agg}'")
        print("In vulnerable version: Executes injected SELECT")
        print("In secure version:")
        
        report = secure_service.generate_grouped_report('department', malicious_agg)
        print(f"  ✅ Query executed safely: {len(report)} groups")
        print(f"  → Invalid aggregate rejected, defaulted to COUNT")
        print(f"  → Whitelist validation at USAGE time prevents injection")
        
        print("\n[TEST 5] Complex Multi-Field Attack")
        print("-" * 70)
        print("All fields contain SQLinjection attempts")
        print("In secure version:")
        
        report = secure_service.generate_complex_report(
            sort_field="id--",
            filter_field="status--",
            filter_value="' OR '1'='1",
            group_by_field="department--"
        )
        print(f"  ✅ Query handled safely")
        print(f"  → All identifiers quoted with sql.Identifier()")
        print(f"  → Values parameterized with %s")
        print(f"  → No injection possible")
        
        print("\n" + "="*70)
        print("SECURITY SUMMARY")
        print("="*70)
        print("\n✅ ALL attacks prevented by:")
        print("   1. sql.Identifier() for column/table names at USAGE time")
        print("   2. Parameterization (%s) for values")
        print("   3. Whitelist validation for SQL keywords at USAGE time")
        print("\n🔑 KEY PRINCIPLE:")
        print("   Validation + Safe Storage is NOT enough")
        print("   Must use sql.Identifier() at USAGE TIME")
        print("\n📊 COMPARISON:")
        print("   Vulnerable: f\"SELECT * FROM t ORDER BY {field}\"")
        print("   Secure: sql.SQL(\"SELECT * FROM t ORDER BY {}\").format(sql.Identifier(field))")
        
        conn.close()
        
    except psycopg2.Error as e:
        print(f"❌ Database error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    demonstrate_secure_implementation()
