from django.db import models
from django.db.models import Count
from django.db.models.functions import Lower

class User(models.Model):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField()
    role = models.CharField(max_length=50)
    department = models.CharField(max_length=100)

    class Meta:
        app_label = '__main__'
        db_table = "auth_user"

class Project(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="owned_projects")
    status = models.CharField(max_length=50)
    priority = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = '__main__'
        db_table = "projects_project"

# STRICT whitelist
ALLOWED_SEARCH_FIELDS = {
"name",
"status",
"priority",
"owner_id"
}

ALLOWED_SORT_FIELDS = {
"name",
"created_at",
"priority",
"status"
}

@classmethod
def search_by_criteria(cls,
search_field, search_value):
"""
FIX:
- Removed raw SQL
- Whitelisted field names
- Uses ORM filtering
"""

if search_field not in cls.ALLOWED_SEARCH_FIELDS:
raise ValueError("Invalid search field")

return list(
cls.objects.filter(**{search_field: search_value})
.order_by("-created_at")
)

@classmethod
def get_projects_with_stats(cls,
sort_field="name", filters=None):
"""
FIX:
- ORM annotation instead of raw SQL
- Whitelisted ordering
- Safe filter dictionary
"""

if sort_field not in cls.ALLOWED_SORT_FIELDS:
raise ValueError("Invalid sort field")

queryset = cls.objects.annotate(
task_count=Count("tasks")
)

if isinstance(filters, dict):
queryset = queryset.filter(**filters)

return list(queryset.order_by(sort_field))

class Task(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="tasks")
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="assigned_tasks")
    status = models.CharField(max_length=50)
    priority = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = '__main__'
        db_table = "projects_task"

ALLOWED_GROUP_FIELDS = {
"status",
"priority",
"assignee_id",
"project_id"
}

@classmethod
def filter_with_raw_sql(cls, filters):
"""
FIX:
- Replace raw SQL expression with
structured filters
"""

if not isinstance(filters, dict):
raise ValueError("Filters must be dict")

return list(
cls.objects.select_related("assignee", "project")
.filter(**filters)
)

@classmethod
def get_tasks_by_criteria(cls,
group_by_field, having_min_count=None):
"""
FIX:
- ORM aggregation
- Safe grouping
"""

if group_by_field not in cls.ALLOWED_GROUP_FIELDS:
raise ValueError("Invalid group field")

queryset = (
cls.objects.values(group_by_field)
.annotate(count=models.Count("id"))
.order_by("-count")
)

if having_min_count is not None:
queryset = queryset.filter(count__gte=having_min_count)

return list(queryset)

class Comment(models.Model):
    content = models.TextField()
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="comments")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = '__main__'
        db_table = "projects_comment"

ALLOWED_ORDER_FIELDS = {
"created_at",
"id"
}

@classmethod
def search_comments(cls, search_term):
"""
FIX:
- Removed dynamic SELECT injection
- ORM safe filtering
"""

return list(
cls.objects.select_related("author", "task")
.filter(content__icontains=search_term)
)

@classmethod
def get_comments_with_filter(cls,
task_id, order_expression):
"""
FIX:
- Strict ORDER BY whitelist
"""

order_field = order_expression.replace(" DESC", "").replace("
ASC", "")

if order_field not in cls.ALLOWED_ORDER_FIELDS:
raise ValueError("Invalid order field")

return list(
cls.objects.select_related("author")
.filter(task_id=task_id)
.order_by(order_expression)
)

✅
FIXED query_builder.py
The original builder is fundamentally unsafe.
We replace it with a safe ORM builder.
"""
SECURE VERSION - query_builder.py

Replaces vulnerable SQL string builder with ORM query
builder.
"""

from django.db.models import Count
from models import Project, Task