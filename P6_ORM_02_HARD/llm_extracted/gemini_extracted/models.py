from django.db import models
from django.db.models import Count, Q, F
from django.db.models.functions import Lower

class User(models.Model):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField()
    role = models.CharField(max_length=50)
    department = models.CharField(max_length=100)

    class Meta:
        app_label = '__main__'
        db_table = 'auth_user'

class Project(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_projects')
    status = models.CharField(max_length=50)
    priority = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = '__main__'
        db_table = 'projects_project'

@classmethod
def search_by_criteria(cls, search_field,
search_value):
"""FIXED: Uses a whitelist for fields and standard ORM
filter for values."""
allowed_fields = ['name', 'status', 'description',
'priority']
if search_field not in allowed_fields:
raise ValueError("Invalid search field")

# Using
dictionary unpacking with filter() ensures
parameterization
return cls.objects.filter(**{search_field: search_value}).order_by('-created_at')

@classmethod
def get_projects_with_stats(cls, sort_field='name',
filter_q=None):
"""FIXED: Replaced raw SQL with annotate()
and validated sort_field."""
allowed_sorts = ['name', 'task_count',
'created_at', '-created_at']
if sort_field not in allowed_sorts:
sort_field = 'name'

queryset = cls.objects.annotate(task_count=Count('tasks'))
if filter_q:
queryset = queryset.filter(filter_q) # filter_q should be a
Q object

return queryset.order_by(sort_field)

class Task(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='tasks')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_tasks')
    status = models.CharField(max_length=50)
    priority = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = '__main__'
        db_table = 'projects_task'

    @classmethod
    def filter_with_safe_params(cls, **filters):
"""FIXED: Removed raw SQL filter. Uses ORM filter kwargs."""
return cls.objects.select_related('assignee', 'project').filter(**filters)

@classmethod
def get_tasks_summary(cls, group_by_field):
"""FIXED: Uses values() and annotate() for grouping instead of raw SQL
strings."""
allowed_groups = ['status', 'priority', 'project__name']
if group_by_field not in allowed_groups:
raise ValueError("Invalid group field")

return cls.objects.values(group_by_field).annotate(
count=Count('id')
).order_by('-count')

class Comment(models.Model):
    content = models.TextField()
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = '__main__'
        db_table = 'projects_comment'

@classmethod
def search_comments_safe(cls, search_term):
"""FIXED: Uses __icontains for
safe LIKE queries."""
return cls.objects.filter(content__icontains=search_term).select_related('author', 'task')

@classmethod
def get_comments_ordered(cls, task_id,
sort_order='-created_at'):
"""FIXED: Validates order and uses standard
filter."""
allowed_orders = ['created_at',
'-created_at', 'author__username']
if sort_order not in allowed_orders:
sort_order = '-created_at'

return cls.objects.filter(task_id=task_id).select_related('author').order_by(sort_order)

File: query_builder.py

from django.db.models
import Q, Count
from models import Project