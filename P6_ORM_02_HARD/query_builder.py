"""
Query Builder - Complex query construction with chaining
Additional injection vulnerabilities through builder pattern
"""

from django.db import connection
from models import Project, Task, User, Comment


class ProjectQueryBuilder:
    """
    Builder pattern for complex project queries
    Accumulates query parts and executes with .raw()
    """
    
    def __init__(self):
        self.select_fields = ['p.*']
        self.joins = []
        self.where_conditions = []
        self.group_by = None
        self.having = None
        self.order_by = None
    
    def select(self, fields):
        """
        Add custom SELECT fields
        INJECTION POINT #8: Accumulated SELECT fields
        """
        # Validation: Non-empty check
        if not fields:
            raise ValueError("Fields cannot be empty")
        
        # VULNERABLE: Accumulates user input for SELECT
        if isinstance(fields, list):
            self.select_fields.extend(fields)
        else:
            self.select_fields.append(fields)
        return self
    
    def join(self, join_clause):
        """
        Add JOIN clause
        Potentially vulnerable if join_clause comes from user input
        """
        # VULNERABLE: Direct join clause addition
        self.joins.append(join_clause)
        return self
    
    def where(self, condition):
        """
        Add WHERE condition
        INJECTION POINT #9: Accumulated WHERE conditions
        """
        # Validation: Basic non-empty check
        if not condition or condition.strip() == '':
            raise ValueError("Condition cannot be empty")
        
        # VULNERABLE: Accumulates WHERE conditions
        self.where_conditions.append(condition)
        return self
    
    def group(self, field):
        """Add GROUP BY clause"""
        # VULNERABLE: Direct field injection
        self.group_by = field
        return self
    
    def having_clause(self, condition):
        """
        Add HAVING clause
        INJECTION POINT #10: HAVING condition
        """
        # VULNERABLE: Direct HAVING clause
        self.having = condition
        return self
    
    def order(self, expression):
        """Add ORDER BY"""
        # VULNERABLE: Direct ORDER BY expression
        self.order_by = expression
        return self
    
    def build_and_execute(self):
        """
        Build final query and execute with .raw()
        Combines all accumulated parts into SQL string
        """
        # Build SELECT
        select_clause = ', '.join(self.select_fields)
        query = f"SELECT {select_clause} FROM projects p"
        
        # Add JOINs
        if self.joins:
            query += ' ' + ' '.join(self.joins)
        
        # Add WHERE
        if self.where_conditions:
            where_clause = ' AND '.join(self.where_conditions)
            query += f" WHERE {where_clause}"
        
        # Add GROUP BY
        if self.group_by:
            query += f" GROUP BY {self.group_by}"
        
        # Add HAVING
        if self.having:
            query += f" HAVING {self.having}"
        
        # Add ORDER BY
        if self.order_by:
            query += f" ORDER BY {self.order_by}"
        
        # VULNERABLE: Execute accumulated query with .raw()
        return list(Project.objects.raw(query))


class TaskAggregator:
    """
    Aggregate task data with complex queries
    Uses .extra() and RawSQL() - also vulnerable
    """
    
    @staticmethod
    def get_tasks_with_extra(extra_select, extra_where):
        """
        Use Django .extra() method (deprecated but still used)
        VULNERABLE: .extra() with user-controlled select/where
        """
        # Validation: Type check only
        if not isinstance(extra_select, dict):
            raise TypeError("extra_select must be dict")
        
        # VULNERABLE: .extra() allows SQL injection
        # Django deprecated .extra() for this reason!
        queryset = Task.objects.extra(
            select=extra_select,  # Can contain arbitrary SQL
            where=[extra_where] if extra_where else None
        )
        
        return list(queryset)
    
    @staticmethod
    def filter_with_rawsql(field_name, raw_condition):
        """
        Use RawSQL annotation
        VULNERABLE: RawSQL with unparameterized user input
        """
        # VULNERABLE: RawSQL without parameters
        return list(
            Task.objects.annotate(
                custom_field=RawSQL(f'{field_name}', [])
            ).extra(
                where=[f'{raw_condition}']
            )
        )


def complex_project_search(search_params):
    """
    Complex search combining multiple models
    Uses query builder to construct dynamic query
    """
    builder = ProjectQueryBuilder()
    
    # Add custom SELECT fields if provided
    if 'select_fields' in search_params:
        for field in search_params['select_fields']:
            builder.select(field)
    
    # Add task count join
    builder.join('LEFT JOIN tasks t ON p.id = t.project_id')
    
    # Add WHERE conditions from search params
    if 'where_conditions' in search_params:
        for condition in search_params['where_conditions']:
            builder.where(condition)
    
    # Add GROUP BY if specified
    if 'group_by' in search_params:
        builder.group(search_params['group_by'])
    
    # Add HAVING if specified
    if 'having' in search_params:
        builder.having_clause(search_params['having'])
    
    # Add ORDER BY if specified
    if 'order_by' in search_params:
        builder.order(search_params['order_by'])
    
    return builder.build_and_execute()


def get_user_dashboard_stats(user_id, stat_field, filter_clause):
    """
    Get user dashboard statistics
    Combines data from multiple models
    """
    with connection.cursor() as cursor:
        # VULNERABLE: f-string interpolation in complex query
        query = f"""
            SELECT 
                u.username,
                u.department,
                {stat_field} as stat_value,
                COUNT(DISTINCT p.id) as project_count,
                COUNT(DISTINCT t.id) as task_count
            FROM users u
            LEFT JOIN projects p ON u.id = p.owner_id
            LEFT JOIN tasks t ON u.id = t.assignee_id
            WHERE u.id = %s AND {filter_clause}
            GROUP BY u.id, u.username, u.department, stat_value
        """
        cursor.execute(query, [user_id])
        return cursor.fetchall()
