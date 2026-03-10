from django.db.models import Count

class ProjectQueryBuilder:
"""
SAFE query builder using Django ORM
"""

ALLOWED_SELECT = {
"task_count"
}

ALLOWED_FILTER_FIELDS = {
"status",
"priority",
"owner_id"
}

ALLOWED_GROUP_FIELDS = {
"status",
"priority"
}

ALLOWED_ORDER_FIELDS = {
"name",
"created_at",
"priority"
}

def __init__(self):
self.queryset = Project.objects.all()

def select(self, fields):

if not isinstance(fields, list):
return self

if "task_count" in fields:
self.queryset = self.queryset.annotate(task_count=Count("tasks"))

return self

def where(self, filters):

if not isinstance(filters, dict):
return self

safe_filters = {
k: v for k, v in filters.items()
if k in self.ALLOWED_FILTER_FIELDS
}

self.queryset = self.queryset.filter(**safe_filters)

return self

def group(self, field):

if field not in self.ALLOWED_GROUP_FIELDS:
raise ValueError("Invalid group field")

self.queryset = self.queryset.values(field).annotate(count=Count("id"))

return self

def order(self, field):

if field not in self.ALLOWED_ORDER_FIELDS:
raise ValueError("Invalid order field")

self.queryset = self.queryset.order_by(field)

return self

def build_and_execute(self):
return list(self.queryset)

def complex_project_search(search_params):
"""
SAFE complex search
"""

builder = ProjectQueryBuilder()

if "select_fields" in search_params:
builder.select(search_params["select_fields"])

if "where_conditions" in search_params:
builder.where(search_params["where_conditions"])

if "group_by" in search_params:
builder.group(search_params["group_by"])

if "order_by" in search_params:
builder.order(search_params["order_by"])

return builder.build_and_execute()

def get_user_dashboard_stats(user_id):
"""
FIX: