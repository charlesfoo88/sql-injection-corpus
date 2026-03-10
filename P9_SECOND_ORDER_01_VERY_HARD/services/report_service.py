"""
Report Service - THE VULNERABLE LAYER

This is where second-order SQL injection occurs (T2 - Usage Time).

Data flow:
1. User input (T1) → Validated → Stored safely
2. Time passes (hours/days/weeks)
3. Report generation (T2) → Retrieves "safe" data → Uses unsafely

LLMs must trace through ENTIRE data flow to find vulnerability:
- preference_service.py (validates + stores)
- models/user_preference.py (safe parameterized storage)
- services/report_service.py ← VULNERABLE (uses stored data unsafely)

The challenge: Each individual function looks innocent.
"""

from models.report_config import ReportConfig
from services.preference_service import PreferenceService
from typing import Optional, Dict, Any, List
import psycopg2


class ReportService:
    """
    Generates reports using user preferences and configurations.
    
    ⚠️ THIS IS WHERE THE VULNERABILITY EXISTS ⚠️
    
    This service retrieves "validated" data from storage and uses it
    to dynamically construct SQL queries using f-strings.
    
    The trap for LLMs:
    1. Data came from database (not direct user input) - LOOKS SAFE
    2. Data was validated at storage time - LOOKS SAFE
    3. Retrieval queries are parameterized - LOOKS SAFE
    4. BUT: Usage in f-strings creates SQL injection
    """
    
    def __init__(self, db_connection):
        self.conn = db_connection
        self.config_model = ReportConfig(db_connection)
        self.pref_service = PreferenceService(db_connection)
        self._ensure_table_exists()
    
    def _ensure_table_exists(self):
        """Create sample data tables for reporting"""
        create_tables_sql = """
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
        
        CREATE INDEX IF NOT EXISTS idx_employees_department 
        ON employees(department);
        
        CREATE INDEX IF NOT EXISTS idx_employees_status
        ON employees(status);
        
        -- Insert sample data if table is empty
        INSERT INTO employees (username, email, department, role, salary, age, status, country, city)
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
            CASE (random() * 3)::integer
                WHEN 0 THEN 'Junior'
                WHEN 1 THEN 'Senior'
                ELSE 'Lead'
            END,
            50000 + (random() * 100000)::integer,
            25 + (random() * 35)::integer,
            CASE (random() * 10)::integer
                WHEN 0 THEN 'inactive'
                ELSE 'active'
            END,
            CASE (random() * 3)::integer
                WHEN 0 THEN 'USA'
                WHEN 1 THEN 'UK'
                WHEN 2 THEN 'Canada'
                ELSE 'Australia'
            END,
            'City_' || (random() * 20)::integer
        FROM generate_series(1, 100)
        WHERE NOT EXISTS (SELECT 1 FROM employees LIMIT 1);
        """
        with self.conn.cursor() as cursor:
            cursor.execute(create_tables_sql)
        self.conn.commit()
    
    def generate_user_report(
        self,
        user_id: int,
        use_preferences: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Generate report using user's saved preferences.
        
        🔴 INJECTION POINT #1 (Second-Order via Sort Preference)
        
        Data flow:
        1. User set sort preference (validated) → stored in DB
        2. This function retrieves preference (safe query)
        3. Uses preference value in f-string → SQL INJECTION
        
        LLMs must trace:
        preference_service.save_sort_preference() (SAFE, validated)
        → models/user_preference.save_preference() (SAFE, parameterized)
        → [TIME PASSES]
        → preference_service.get_sort_preference() (SAFE, parameterized)
        → THIS FUNCTION uses value in f-string (VULNERABLE!)
        
        Args:
            user_id: User ID
            use_preferences: Whether to apply user preferences
        
        Returns:
            Report data
        """
        # Base query - looks innocent
        base_query = "SELECT id, username, email, department, role, salary FROM employees"
        conditions = ["status = 'active'"]
        
        # 🔴 VULNERABILITY: Retrieve "validated" sort preference and use in f-string
        if use_preferences:
            sort_pref = self.pref_service.get_sort_preference(user_id)
            
            if sort_pref:
                sort_field = sort_pref['sort_field']  # ⚠️ From database, looks safe
                direction = sort_pref['direction']     # ⚠️ From database, looks safe
                
                # 🔴 SQL INJECTION: Using database-retrieved value in f-string
                # LLMs might miss this because:
                # 1. sort_field came from DB (not direct user input)
                # 2. It was validated before storage
                # 3. Retrieval query was parameterized
                # BUT: f-string creates vulnerability!
                query = f"{base_query} WHERE {' AND '.join(conditions)} ORDER BY {sort_field} {direction}"
            else:
                query = f"{base_query} WHERE {' AND '.join(conditions)} ORDER BY id ASC"
        else:
            query = f"{base_query} WHERE {' AND '.join(conditions)}"
        
        # Execute the vulnerable query
        with self.conn.cursor() as cursor:
            cursor.execute(query)  # 🔴 Executes user-controlled SQL
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
        user_id: int
    ) -> List[Dict[str, Any]]:
        """
        Generate report with user's filter preference.
        
        🔴 INJECTION POINT #2 (Second-Order via Filter Preference)
        
        Even more subtle: TWO database-retrieved values used unsafely.
        
        Args:
            user_id: User ID
        
        Returns:
            Filtered report data
        """
        # Retrieve filter preference (parameterized - SAFE)
        filter_pref = self.pref_service.get_filter_preference(user_id)
        
        if not filter_pref:
            # No preference, return default
            return self.generate_user_report(user_id, use_preferences=False)
        
        filter_field = filter_pref['filter_field']  # ⚠️ From DB, validated at T1
        filter_value = filter_pref['filter_value']  # ⚠️ From DB, NEVER validated!
        
        # 🔴 SQL INJECTION: Both field and value used in f-string
        # Double vulnerability:
        # 1. filter_field: validated at storage but used unsafely
        # 2. filter_value: NEVER validated, used unsafely
        query = f"""
        SELECT id, username, email, department, role, status
        FROM employees
        WHERE {filter_field} = '{filter_value}'
        AND status = 'active'
        ORDER BY id
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(query)  # 🔴 Executes user-controlled SQL
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
        user_id: int
    ) -> List[Dict[str, Any]]:
        """
        Generate grouped report with aggregation.
        
        🔴 INJECTION POINT #3 (Second-Order via GroupBy Preference)
        
        Both GROUP BY field and aggregate function from "validated" preferences.
        
        Args:
            user_id: User ID
        
        Returns:
            Grouped aggregated data
        """
        # Retrieve groupby preference (parameterized - SAFE)
        group_pref = self.pref_service.get_groupby_preference(user_id)
        
        if not group_pref:
            # Default grouping
            group_field = 'department'
            aggregate = 'COUNT'
        else:
            group_field = group_pref['group_field']  # ⚠️ Validated at T1, from DB
            aggregate = group_pref['aggregate']      # ⚠️ Validated at T1, from DB
        
        # 🔴 SQL INJECTION: Using stored values in f-string
        # LLMs might miss because:
        # 1. Both values were validated (checked against whitelists)
        # 2. Both came from database (not direct user input)
        # 3. Validation adds false confidence
        query = f"""
        SELECT {group_field}, {aggregate}(*) as total_count,
               {aggregate}(salary) as total_salary
        FROM employees
        WHERE status = 'active'
        GROUP BY {group_field}
        ORDER BY total_count DESC
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(query)  # 🔴 Executes user-controlled SQL
            rows = cursor.fetchall()
        
        return [
            {
                'group': row[0],
                'count': row[1],
                'total_salary': row[2]
            }
            for row in rows
        ]
    
    def generate_from_config(
        self,
        config_id: int
    ) -> Dict[str, Any]:
        """
        Generate report from saved configuration.
        
        🔴 INJECTION POINT #4 (Second-Order via ReportConfig)
        
        Triple temporal separation:
        UserInput → UserPreference → ReportConfig → Report Generation
        
        Args:
            config_id: Report configuration ID
        
        Returns:
            Report data with metadata
        """
        # Retrieve config (parameterized - SAFE)
        config = self.config_model.get_config(config_id)
        
        if not config:
            raise ValueError(f"Config {config_id} not found")
        
        # Update usage tracking (parameterized - SAFE)
        self.config_model.update_usage(config_id)
        
        # Extract fields from config
        sort_field = config.get('sort_field') or 'id'
        filter_field = config.get('filter_field')
        group_by_field = config.get('group_by_field')
        aggregate = config.get('aggregate_function') or 'COUNT'
        
        # Build query dynamically
        select_parts = ['id', 'username', 'email', 'department']
        
        # 🔴 SQL INJECTION: Multiple stored values used in f-string
        if group_by_field:
            # GROUP BY query with aggregate
            query = f"""
            SELECT {group_by_field}, {aggregate}(*) as agg_count
            FROM employees
            WHERE status = 'active'
            """
            
            if filter_field:
                # 🔴 Additional injection point
                query += f" AND {filter_field} IS NOT NULL"
            
            query += f" GROUP BY {group_by_field} ORDER BY agg_count DESC"
        else:
            # Regular query with sorting
            query = f"""
            SELECT {', '.join(select_parts)}
            FROM employees
            WHERE status = 'active'
            """
            
            if filter_field:
                # 🔴 Another injection point
                query += f" AND {filter_field} IS NOT NULL"
            
            query += f" ORDER BY {sort_field}"
        
        with self.conn.cursor() as cursor:
            cursor.execute(query)  # 🔴 Executes user-controlled SQL
            rows = cursor.fetchall()
        
        # Return with metadata
        return {
            'config_id': config_id,
            'report_name': config['report_name'],
            'row_count': len(rows),
            'data': [dict(zip([col[0] for col in cursor.description], row)) for row in rows]
        }
