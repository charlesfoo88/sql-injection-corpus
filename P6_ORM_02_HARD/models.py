"""
Project Management - Django Models
Multi-model architecture with ORM SQL injection vulnerabilities
"""

from django.db import models
from django.db.models import RawSQL


class User(models.Model):
    """User model"""
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField()
    role = models.CharField(max_length=50)
    department = models.CharField(max_length=100)
    
    class Meta:
        db_table = 'users'


class Project(models.Model):
    """Project model"""
    name = models.CharField(max_length=200)
    description = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_projects')
    status = models.CharField(max_length=50)
    priority = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'projects'
    
    @classmethod
    def search_by_criteria(cls, search_field, search_value):
        """
        Search projects by dynamic field
        INJECTION POINT #1: Dynamic field name in WHERE clause
        """
        # Validation: Check if field name is alphanumeric (weak)
        if not search_field.replace('_', '').isalnum():
            raise ValueError("Invalid field name")
        
        # VULNERABLE: f-string in .raw() with dynamic field name
        query = f"""
            SELECT * FROM projects 
            WHERE {search_field} = %s
            ORDER BY created_at DESC
        """
        return list(cls.objects.raw(query, [search_value]))
    
    @classmethod
    def get_projects_with_stats(cls, sort_field='name', filters=None):
        """
        Get projects with task statistics
        INJECTION POINT #2: ORDER BY with aggregation
        """
        # Validation: Check if sort_field looks like column name
        if not sort_field.replace('_', '').replace('.', '').isalnum():
            raise ValueError("Invalid sort field")
        
        # VULNERABLE: f-string in ORDER BY with joins
        base_query = """
            SELECT p.*, COUNT(t.id) as task_count
            FROM projects p
            LEFT JOIN tasks t ON p.id = t.project_id
        """
        
        if filters:
            # Additional vulnerability from filters
            base_query += f" WHERE {filters}"
        
        # VULNERABLE: f-string in ORDER BY
        query = base_query + f" GROUP BY p.id ORDER BY {sort_field}"
        
        return list(cls.objects.raw(query))


class Task(models.Model):
    """Task model"""
    title = models.CharField(max_length=200)
    description = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='tasks')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_tasks')
    status = models.CharField(max_length=50)
    priority = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'tasks'
    
    @classmethod
    def filter_with_raw_sql(cls, filter_expression):
        """
        Filter tasks using raw SQL expression
        INJECTION POINT #3: WHERE clause expression
        """
        # Validation: Empty check only
        if not filter_expression or filter_expression.strip() == '':
            raise ValueError("Filter expression required")
        
        # VULNERABLE: Direct filter expression in WHERE
        query = f"""
            SELECT t.*, u.username as assignee_name, p.name as project_name
            FROM tasks t
            LEFT JOIN users u ON t.assignee_id = u.id
            LEFT JOIN projects p ON t.project_id = p.id
            WHERE {filter_expression}
        """
        return list(cls.objects.raw(query))
    
    @classmethod
    def get_tasks_by_criteria(cls, group_by_field, having_clause=None):
        """
        Get tasks grouped by field with optional HAVING clause
        INJECTION POINT #4: GROUP BY and HAVING clauses
        """
        # Validation: Basic alphanumeric check
        if not group_by_field.replace('_', '').replace('.', '').isalnum():
            raise ValueError("Invalid group field")
        
        # VULNERABLE: f-string in GROUP BY
        query = f"""
            SELECT {group_by_field}, COUNT(*) as count, 
                   STRING_AGG(title, ', ') as titles
            FROM tasks
            GROUP BY {group_by_field}
        """
        
        # INJECTION POINT #5: HAVING clause (if provided)
        if having_clause:
            # VULNERABLE: Direct HAVING clause injection
            query += f" HAVING {having_clause}"
        
        query += " ORDER BY count DESC"
        
        return list(cls.objects.raw(query))


class Comment(models.Model):
    """Comment model"""
    content = models.TextField()
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'comments'
    
    @classmethod
    def search_comments(cls, search_columns, search_term):
        """
        Search comments across multiple columns
        INJECTION POINT #6: SELECT column list with CONCAT
        """
        # Validation: Check if columns contain expected keywords
        expected = ['content', 'author', 'task', 'created_at']
        if not any(kw in search_columns.lower() for kw in expected):
            raise ValueError("Must include valid columns")
        
        # VULNERABLE: Column list in SELECT with CONCAT
        query = f"""
            SELECT c.id, c.content, c.created_at,
                   {search_columns} as search_field,
                   u.username as author_name,
                   t.title as task_title
            FROM comments c
            JOIN users u ON c.author_id = u.id
            JOIN tasks t ON c.task_id = t.id
            WHERE LOWER(c.content) LIKE %s
        """
        return list(cls.objects.raw(query, [f'%{search_term}%']))
    
    @classmethod
    def get_comments_with_filter(cls, task_id, order_expression):
        """
        Get comments for a task with custom ordering
        INJECTION POINT #7: ORDER BY with expressions
        """
        # Validation: Parameter type check only
        if not isinstance(task_id, (int, str)):
            raise TypeError("task_id must be int or string")
        
        # VULNERABLE: ORDER BY expression injection
        query = f"""
            SELECT c.*, u.username as author_name
            FROM comments c
            JOIN users u ON c.author_id = u.id
            WHERE c.task_id = %s
            ORDER BY {order_expression}
        """
        return list(cls.objects.raw(query, [task_id]))
