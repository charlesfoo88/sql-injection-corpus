"""
Report Configuration Model - Another Safe Storage Layer

This adds another layer of temporal separation:
Input → UserPreference → ReportConfig → Report Generation

Each layer looks individually secure, making the vulnerability harder to trace.
"""

import psycopg2
from datetime import datetime
import json
from typing import Optional, Dict, Any, List


class ReportConfig:
    """
    Stores report configurations built from user preferences.
    
    This is a second storage layer that ALSO uses proper parameterization.
    Creates additional temporal distance from original user input.
    """
    
    def __init__(self, db_connection):
        self.conn = db_connection
        self._ensure_table_exists()
    
    def _ensure_table_exists(self):
        """Create report_configs table"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS report_configs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            report_name VARCHAR(200) NOT NULL,
            sort_field VARCHAR(100),
            filter_field VARCHAR(100),
            group_by_field VARCHAR(100),
            aggregate_function VARCHAR(50),
            config_data JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            use_count INTEGER DEFAULT 0
        );
        
        CREATE INDEX IF NOT EXISTS idx_report_configs_user_id 
        ON report_configs(user_id);
        """
        with self.conn.cursor() as cursor:
            cursor.execute(create_table_sql)
        self.conn.commit()
    
    def create_config(
        self,
        user_id: int,
        report_name: str,
        sort_field: Optional[str] = None,
        filter_field: Optional[str] = None,
        group_by_field: Optional[str] = None,
        aggregate_function: Optional[str] = None,
        config_data: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Create report configuration with PROPER PARAMETERIZATION.
        
        ✅ SECURE: All parameters properly passed
        ✅ SECURE: No string concatenation
        
        These fields (sort_field, filter_field, etc.) often come from
        UserPreference.get_preference() - which retrieved them safely.
        
        The trap: Safe retrieval + Safe storage ≠ Safe usage
        
        Args:
            user_id: User ID
            report_name: Name of the report
            sort_field: Field to sort by (PAYLOAD MAY BE HERE)
            filter_field: Field to filter by (PAYLOAD MAY BE HERE)
            group_by_field: Field to group by (PAYLOAD MAY BE HERE)
            aggregate_function: Aggregate to apply (PAYLOAD MAY BE HERE)
            config_data: Additional configuration
        
        Returns:
            Config ID
        """
        config_data = config_data or {}
        config_data['created'] = datetime.now().isoformat()
        
        # ✅ PROPERLY PARAMETERIZED INSERT
        # Even though sort_field/filter_field/group_by_field MAY contain
        # SQL injection payloads, they're safely stored here
        insert_sql = """
        INSERT INTO report_configs 
            (user_id, report_name, sort_field, filter_field, 
             group_by_field, aggregate_function, config_data)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(
                insert_sql,
                (
                    user_id,
                    report_name,
                    sort_field,        # ⚠️ May contain payload
                    filter_field,      # ⚠️ May contain payload
                    group_by_field,    # ⚠️ May contain payload
                    aggregate_function,  # ⚠️ May contain payload
                    json.dumps(config_data)
                )
            )
            config_id = cursor.fetchone()[0]
        
        self.conn.commit()
        return config_id
    
    def get_config(self, config_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve report configuration with PROPER PARAMETERIZATION.
        
        ✅ SECURE: Parameterized SELECT
        
        Returns "safe" data from database that contains sleeping payloads.
        """
        select_sql = """
        SELECT id, user_id, report_name, sort_field, filter_field,
               group_by_field, aggregate_function, config_data,
               created_at, last_used, use_count
        FROM report_configs
        WHERE id = %s;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(select_sql, (config_id,))
            row = cursor.fetchone()
        
        if not row:
            return None
        
        return {
            'id': row[0],
            'user_id': row[1],
            'report_name': row[2],
            'sort_field': row[3],        # ⚠️ Payload waiting
            'filter_field': row[4],      # ⚠️ Payload waiting
            'group_by_field': row[5],    # ⚠️ Payload waiting
            'aggregate_function': row[6],  # ⚠️ Payload waiting
            'config_data': row[7],
            'created_at': row[8],
            'last_used': row[9],
            'use_count': row[10]
        }
    
    def get_user_configs(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all report configs for a user (parameterized)"""
        select_sql = """
        SELECT id, report_name, sort_field, filter_field,
               group_by_field, aggregate_function, use_count
        FROM report_configs
        WHERE user_id = %s
        ORDER BY last_used DESC NULLS LAST, report_name;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(select_sql, (user_id,))
            rows = cursor.fetchall()
        
        return [
            {
                'id': row[0],
                'report_name': row[1],
                'sort_field': row[2],
                'filter_field': row[3],
                'group_by_field': row[4],
                'aggregate_function': row[5],
                'use_count': row[6]
            }
            for row in rows
        ]
    
    def update_usage(self, config_id: int):
        """Track when config was last used (parameterized)"""
        update_sql = """
        UPDATE report_configs
        SET last_used = CURRENT_TIMESTAMP,
            use_count = use_count + 1
        WHERE id = %s;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(update_sql, (config_id,))
        
        self.conn.commit()
