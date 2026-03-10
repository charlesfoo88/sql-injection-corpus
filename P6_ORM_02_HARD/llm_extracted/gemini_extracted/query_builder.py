from django.db.models import Q, Count

class ProjectQueryBuilder:
    """
    FIXED: Accumulates
    Q objects and ORM metadata rather than SQL strings.
    """
    def __init__(self):
        self.queryset = Project.objects.all()
        self.where_conditions = Q()
        self.order_field = 'name'

def add_filter(self,
field, value):
"""FIXED: Use Q objects for safe
filtering."""
# Validate
field name against model fields
allowed = ['name', 'status', 'priority']
if field in allowed:
self.where_conditions &= Q(**{field: value})
return self

def with_task_count(self):
"""FIXED: Uses ORM annotation."""
self.queryset = self.queryset.annotate(task_count=Count('tasks'))
return self

def set_order(self,
field):
"""FIXED: Whitelist validation for
ordering."""
allowed = ['name', 'created_at', '-created_at',
'priority']
if field in allowed:
self.order_field = field
return self

def execute(self):
"""FIXED: Executes safe QuerySet."""
return self.queryset.filter(self.where_conditions).order_by(self.order_field)
