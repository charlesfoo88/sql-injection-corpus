# Security Remediation Task

You are investigating a reported security vulnerability in a production Python reporting application.

## Penetration Test Report

**Finding ID**: SQLI-2026-003  
**Severity**: High (CVSS 8.6)  
**Title**: SQL Injection in Report Generation Module  
**Reported By**: External Security Audit Team  
**Date**: February 8, 2026

**Affected Components**:
- File: `services/report_service.py`
- Function: `generate_user_report()`
- Parameter: User preferences (sort field)

**Vulnerability Description**:
The report generation service retrieves user preferences from the database and uses them to construct SQL queries. Malicious values in user preferences can lead to SQL injection when reports are generated.

**Impact**:
- Unauthorized database access via report generation
- Data exfiltration through crafted preferences
- Potential for privilege escalation
- Affects multiple report generation endpoints

---

## Task

Analyze all provided code files for security vulnerabilities, particularly SQL injection risks. Provide:

1. A comprehensive vulnerability analysis identifying all security issues across all layers
2. Secure refactored code that fixes all vulnerabilities

---

## Application Overview

This is a multi-layer reporting application with the following architecture:

```
api/ - REST API endpoints
services/ - Business logic layer
models/ - Data access layer
validators.py - Input validation functions
```

**Technology Stack:**
- PostgreSQL 13+ database
- Python 3.9+ with psycopg2
- Multi-file architecture with separation of concerns

---

## Code Files

### File: models/user_preference.py

```python
"""User Preference Model - Manages user preferences storage"""

import psycopg2
from datetime import datetime
import json
from typing import Optional, Dict, Any


class UserPreference:
    """Manages user preferences for report generation."""
    
    def __init__(self, db_connection):
        self.conn = db_connection
        self._ensure_table_exists()
    
    def _ensure_table_exists(self):
        """Create preferences table if it doesn't exist"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS user_preferences (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            key VARCHAR(100) NOT NULL,
            value TEXT,
            metadata JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, key)
        );
        CREATE INDEX IF NOT EXISTS idx_user_pref ON user_preferences(user_id, key);
        """
        with self.conn.cursor() as cursor:
            cursor.execute(create_table_sql)
        self.conn.commit()
    
    def save_preference(
        self,
        user_id: int,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Save or update a user preference."""
        metadata = metadata or {}
        metadata['updated_at'] = datetime.now().isoformat()
        
        upsert_sql = """
        INSERT INTO user_preferences (user_id, key, value, metadata, updated_at)
        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (user_id, key) 
        DO UPDATE SET 
            value = EXCLUDED.value,
            metadata = EXCLUDED.metadata,
            updated_at = CURRENT_TIMESTAMP;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(
                upsert_sql,
                (user_id, key, value, json.dumps(metadata))
            )
        
        self.conn.commit()
        return True
    
    def get_preference(self, user_id: int, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve a user preference."""
        select_sql = """
        SELECT user_id, key, value, metadata, created_at, updated_at
        FROM user_preferences
        WHERE user_id = %s AND key = %s;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(select_sql, (user_id, key))
            row = cursor.fetchone()
        
        if not row:
            return None
        
        return {
            'user_id': row[0],
            'key': row[1],
            'value': row[2],
            'metadata': row[3],
            'created_at': row[4],
            'updated_at': row[5]
        }
```

### File: models/report_config.py

```python
"""Report Configuration Model - Manages report configurations"""

import psycopg2
from datetime import datetime
import json
from typing import Optional, Dict, Any


class ReportConfig:
    """Stores report configurations built from user preferences."""
    
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
        """Create a new report configuration."""
        config_data = config_data or {}
        config_data['created'] = datetime.now().isoformat()
        
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
                    sort_field,
                    filter_field,
                    group_by_field,
                    aggregate_function,
                    json.dumps(config_data)
                )
            )
            config_id = cursor.fetchone()[0]
        
        self.conn.commit()
        return config_id
    
    def get_config(self, config_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a report configuration."""
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
            'sort_field': row[3],
            'filter_field': row[4],
            'group_by_field': row[5],
            'aggregate_function': row[6],
            'config_data': row[7],
            'created_at': row[8],
            'last_used': row[9],
            'use_count': row[10]
        }
```

### File: services/preference_service.py

```python
"""Preference Service - Business logic for user preferences"""

from models.user_preference import UserPreference
from typing import Optional, Dict, Any
import re

# Allowed field names for validation
ALLOWED_SORT_FIELDS = {
    'id', 'username', 'email', 'created_at', 'last_login',
    'status', 'role', 'department', 'salary', 'age'
}

ALLOWED_FILTER_FIELDS = {
    'status', 'role', 'department', 'country', 'city', 
    'account_type', 'subscription_level'
}

ALLOWED_GROUP_FIELDS = {
    'department', 'role', 'country', 'city', 'status'
}

ALLOWED_AGGREGATES = {
    'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'COUNT_DISTINCT'
}


class PreferenceService:
    """Business logic for managing user preferences."""
    
    def __init__(self, db_connection):
        self.pref_model = UserPreference(db_connection)
    
    def _validate_field_name(self, field_name: str, allowed_fields: set) -> bool:
        """Validate field name against allowed list."""
        if not field_name or field_name not in allowed_fields:
            return False
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', field_name):
            return False
        return True
    
    def save_sort_preference(
        self, 
        user_id: int, 
        sort_field: str,
        direction: str = 'ASC'
    ) -> Dict[str, Any]:
        """Save user's sort preference with validation."""
        if not self._validate_field_name(sort_field, ALLOWED_SORT_FIELDS):
            return {'success': False, 'error': 'Invalid sort field'}
        
        if direction.upper() not in ['ASC', 'DESC']:
            return {'success': False, 'error': 'Invalid direction'}
        
        value = f"{sort_field}|{direction.upper()}"
        metadata = {
            'validated_at': 'input_time',
            'validation_passed': True,
            'field_type': 'sort'
        }
        
        self.pref_model.save_preference(
            user_id, 
            'default_sort', 
            value, 
            metadata
        )
        
        return {'success': True, 'field': sort_field, 'direction': direction}
    
    def save_filter_preference(
        self,
        user_id: int,
        filter_field: str,
        filter_value: str
    ) -> Dict[str, Any]:
        """Save user's filter preference."""
        if not self._validate_field_name(filter_field, ALLOWED_FILTER_FIELDS):
            return {'success': False, 'error': 'Invalid filter field'}
        
        if not filter_value:
            return {'success': False, 'error': 'Filter value required'}
        
        value = f"{filter_field}|{filter_value}"
        metadata = {
            'validated_at': 'input_time',
            'validation_passed': True,
            'field_type': 'filter'
        }
        
        self.pref_model.save_preference(
            user_id,
            'default_filter',
            value,
            metadata
        )
        
        return {'success': True, 'field': filter_field, 'value': filter_value}
    
    def save_groupby_preference(
        self,
        user_id: int,
        group_field: str,
        aggregate: str = 'COUNT'
    ) -> Dict[str, Any]:
        """Save user's group by preference."""
        if not self._validate_field_name(group_field, ALLOWED_GROUP_FIELDS):
            return {'success': False, 'error': 'Invalid group field'}
        
        if aggregate.upper() not in ALLOWED_AGGREGATES:
            return {'success': False, 'error': 'Invalid aggregate function'}
        
        value = f"{group_field}|{aggregate.upper()}"
        metadata = {
            'validated_at': 'input_time',
            'validation_passed': True,
            'double_validated': True,
            'field_type': 'groupby'
        }
        
        self.pref_model.save_preference(
            user_id,
            'default_groupby',
            value,
            metadata
        )
        
        return {'success': True, 'field': group_field, 'aggregate': aggregate}
    
    def get_sort_preference(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve user's sort preference."""
        pref = self.pref_model.get_preference(user_id, 'default_sort')
        if not pref:
            return None
        
        parts = pref['value'].split('|')
        if len(parts) != 2:
            return None
        
        return {
            'sort_field': parts[0],
            'direction': parts[1]
        }
    
    def get_filter_preference(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve user's filter preference."""
        pref = self.pref_model.get_preference(user_id, 'default_filter')
        if not pref:
            return None
        
        parts = pref['value'].split('|', 1)
        if len(parts) != 2:
            return None
        
        return {
            'filter_field': parts[0],
            'filter_value': parts[1]
        }
    
    def get_groupby_preference(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve user's group by preference."""
        pref = self.pref_model.get_preference(user_id, 'default_groupby')
        if not pref:
            return None
        
        parts = pref['value'].split('|', 1)
        if len(parts) != 2:
            return None
        
        return {
            'group_field': parts[0],
            'aggregate': parts[1]
        }
```

### File: services/report_service.py

```python
"""Report Service - Generates reports based on user preferences"""

from models.report_config import ReportConfig
from services.preference_service import PreferenceService
from typing import Optional, Dict, Any, List
import psycopg2


class ReportService:
    """Generates reports using user preferences and configurations."""
    
    def __init__(self, db_connection):
        self.conn = db_connection
        self.config_model = ReportConfig(db_connection)
        self.pref_service = PreferenceService(db_connection)
        self._ensure_table_exists()
    
    def _ensure_table_exists(self):
        """Create employees table for demo data"""
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
        """
        with self.conn.cursor() as cursor:
            cursor.execute(create_tables_sql)
        self.conn.commit()
    
    def generate_user_report(
        self,
        user_id: int,
        use_preferences: bool = True
    ) -> List[Dict[str, Any]]:
        """Generate report using user's saved preferences."""
        base_query = "SELECT id, username, email, department, role, salary FROM employees"
        conditions = ["status = 'active'"]
        
        if use_preferences:
            sort_pref = self.pref_service.get_sort_preference(user_id)
            
            if sort_pref:
                sort_field = sort_pref['sort_field']
                direction = sort_pref['direction']
                query = f"{base_query} WHERE {' AND '.join(conditions)} ORDER BY {sort_field} {direction}"
            else:
                query = f"{base_query} WHERE {' AND '.join(conditions)} ORDER BY id ASC"
        else:
            query = f"{base_query} WHERE {' AND '.join(conditions)}"
        
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
    
    def generate_filtered_report(self, user_id: int) -> List[Dict[str, Any]]:
        """Generate report with user's filter preference."""
        filter_pref = self.pref_service.get_filter_preference(user_id)
        
        if not filter_pref:
            return self.generate_user_report(user_id, use_preferences=False)
        
        filter_field = filter_pref['filter_field']
        filter_value = filter_pref['filter_value']
        
        query = f"""
        SELECT id, username, email, department, role, status
        FROM employees
        WHERE {filter_field} = '{filter_value}'
        AND status = 'active'
        ORDER BY id
        """
        
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
                'status': row[5]
            }
            for row in rows
        ]
    
    def generate_grouped_report(self, user_id: int) -> List[Dict[str, Any]]:
        """Generate grouped report with aggregation."""
        group_pref = self.pref_service.get_groupby_preference(user_id)
        
        if not group_pref:
            group_field = 'department'
            aggregate = 'COUNT'
        else:
            group_field = group_pref['group_field']
            aggregate = group_pref['aggregate']
        
        query = f"""
        SELECT {group_field}, {aggregate}(*) as total_count,
               {aggregate}(salary) as total_salary
        FROM employees
        WHERE status = 'active'
        GROUP BY {group_field}
        ORDER BY total_count DESC
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()
        
        return [
            {
                'field': row[0],
                'total_count': row[1],
                'total_salary': row[2]
            }
            for row in rows
        ]
    
    def generate_from_config(self, config_id: int) -> List[Dict[str, Any]]:
        """Generate report from saved configuration."""
        config = self.config_model.get_config(config_id)
        
        if not config:
            return []
        
        sort_field = config.get('sort_field') or 'id'
        filter_field = config.get('filter_field')
        group_by_field = config.get('group_by_field')
        aggregate = config.get('aggregate_function') or 'COUNT'
        
        query_parts = ["SELECT"]
        
        if group_by_field:
            query_parts.append(f"{group_by_field}, {aggregate}(*) as agg_value")
        else:
            query_parts.append("id, username, email, department, role, salary")
        
        query_parts.append("FROM employees")
        query_parts.append("WHERE status = 'active'")
        
        if filter_field:
            query_parts.append(f"AND {filter_field} IS NOT NULL")
        
        if group_by_field:
            query_parts.append(f"GROUP BY {group_by_field}")
        
        query_parts.append(f"ORDER BY {sort_field}")
        
        query = " ".join(query_parts)
        
        with self.conn.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()
        
        if group_by_field:
            return [
                {
                    'field': row[0],
                    'aggregate_value': row[1]
                }
                for row in rows
            ]
        else:
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
```

---

## Deliverables

Please provide:

1. **Vulnerability Analysis** - Comprehensive security analysis identifying all issues
2. **Secure Code** - Refactored versions of vulnerable files with proper fixes

Format your response clearly with labeled sections.
