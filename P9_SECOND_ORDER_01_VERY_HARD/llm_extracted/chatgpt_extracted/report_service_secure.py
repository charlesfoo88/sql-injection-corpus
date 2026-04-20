"""
ChatGPT's Secure Report Service for P9_01
Extracted from OpenAI P09_01.htm

NOTE: This implementation uses validation + f-strings approach.
According to the analysis, this is VULNERABLE because f-strings 
perform string concatenation even after validation.

Correct fix requires: psycopg2.sql.Identifier() for syntax-level protection.
"""

from typing import List, Dict, Any
from sql_safe import safe_column, safe_aggregate


def generate_user_report(self, user_id: int) -> List[Dict[str, Any]]:
    """Generate user report with safe column sorting"""
    sort_pref = self.pref_service.get_sort_preference(user_id)
    
    sort_col = 'id'
    direction = 'ASC'
    
    if sort_pref:
        sort_col = safe_column(sort_pref['sort_field'])
        direction = 'DESC' if sort_pref['direction'] == 'DESC' else 'ASC'
    
    query = f"""
        SELECT id, username, email, department, role, salary
        FROM employees
        WHERE status = %s
        ORDER BY {sort_col} {direction}
    """
    
    with self.conn.cursor() as cursor:
        cursor.execute(query, ('active',))
        rows = cursor.fetchall()
    
    return [...]


def generate_filtered_report(self, user_id: int):
    """Generate filtered report with safe column and parameterized value"""
    pref = self.pref_service.get_filter_preference(user_id)
    if not pref:
        return self.generate_user_report(user_id)
    
    column = safe_column(pref['filter_field'])
    value = pref['filter_value']
    
    query = f"""
        SELECT id, username, email, department, role, status
        FROM employees
        WHERE {column} = %s AND status = %s
    """
    
    with self.conn.cursor() as cursor:
        cursor.execute(query, (value, 'active'))
        rows = cursor.fetchall()
    
    return [...]


def generate_grouped_report(self, user_id: int):
    """Generate grouped report with safe column and aggregate"""
    pref = self.pref_service.get_groupby_preference(user_id)
    
    group_col = safe_column(pref['group_field']) if pref else 'department'
    aggregate = safe_aggregate(pref['aggregate']) if pref else 'COUNT'
    
    query = f"""
        SELECT {group_col},
               {aggregate}(*) AS total_count,
               {aggregate}(salary) AS total_salary
        FROM employees
        WHERE status = %s
        GROUP BY {group_col}
        ORDER BY total_count DESC
    """
    
    with self.conn.cursor() as cursor:
        cursor.execute(query, ('active',))
        rows = cursor.fetchall()
    
    return [...]


def generate_from_config(self, config_id: int):
    """Generate report from config with safe column sorting"""
    config = self.config_model.get_config(config_id)
    if not config:
        return []
    
    sort_col = safe_column(config.get('sort_field') or 'id')
    
    query = f"""
        SELECT id, username, email, department, role, salary
        FROM employees
        WHERE status = %s
        ORDER BY {sort_col}
    """
    
    with self.conn.cursor() as cursor:
        cursor.execute(query, ('active',))
        rows = cursor.fetchall()
    
    return [...]
