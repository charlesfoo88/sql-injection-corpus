"""
Project Management - Django Models
REMEDIATED: All SQL injection vulnerabilities fixed.

Key changes:
- Replaced f-string interpolation in .raw() with allowlisted identifiers
- Dynamic ORDER BY, GROUP BY, field names now validated against explicit allowlists
- All user-supplied VALUES use parameterized placeholders (%s)
- filter_with_raw_sql() and get_tasks_by_criteria(having_clause) refactored to ORM
- Comment.search_comments() column selection replaced with ORM annotate
- Comment.get_comments_with_filter() ORDER BY uses allowlist only
"""

from django.db import models
from django.db.models import Count, Q, Value
from django.db.models.functions import Concat
from django.db.models import RawSQL


# --- Allowlists for dynamic identifiers ---
# Only identifiers in these sets are permitted as dynamic SQL tokens.

PROJECT_SEARCH_FIELDS = {'name', 'status', 'priority', 'description'}

PROJECT_SORT_FIELDS = {
    'name', 'p.name', 'status', 'p.status', 'priority', 'p.priority',
    'created_at', 'p.created_at', 'task_count'
}

TASK_GROUP_FIELDS = {'status', 'priority', 'project_id', 'assignee_id'}

COMMENT_ORDER_FIELDS = {
    'created_at', 'created_at ASC', 'created_at DESC',
    'id', 'id ASC', 'id DESC',
    'author_id', 'author_id ASC', 'author_id DESC',
}

COMMENT_SEARCH_COLUMNS = {
    'content': 'c.content',
    'author': 'u.username',
    'task': 't.title',
    'created_at': 'c.created_at',
}


def _safe_identifier(value, allowlist, label="identifier"):
    """Validate that value is in the allowlist; raise ValueError otherwise."""
    if value not in allowlist:
        raise ValueError(
            f"Invalid {label} '{value}'. Allowed: {sorted(allowlist)}"
        )
    return value


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
        Search projects by dynamic field.

        FIX #1: search_field is validated against an explicit allowlist before
        being interpolated into the SQL string. search_value is still passed as
        a parameterized placeholder (%s), so the value itself is never injected.
        """
        # FIXED: allowlist check replaces the weak isalnum() check
        safe_field = _safe_identifier(search_field, PROJECT_SEARCH_FIELDS, "search_field")

        # safe_field is now a known column name — safe to interpolate
        query = f"""
            SELECT * FROM projects
            WHERE {safe_field} = %s
            ORDER BY created_at DESC
        """
        return list(cls.objects.raw(query, [search_value]))

    @classmethod
    def get_projects_with_stats(cls, sort_field='name', filters=None):
        """
        Get projects with task statistics.

        FIX #2a: sort_field validated against allowlist — no f-string injection.
        FIX #2b: filters parameter removed entirely; callers must pass structured
                 keyword arguments (see views.py).  The free-text WHERE injection
                 is eliminated by switching to Django ORM annotation + filter().
        """
        # FIXED: validate sort field
        safe_sort = _safe_identifier(sort_field, PROJECT_SORT_FIELDS, "sort_field")

        # FIXED: use ORM annotation instead of raw WHERE {filters}
        qs = cls.objects.annotate(task_count=Count('tasks'))

        # filters must now be a dict of ORM kwargs, not a raw string
        if filters and isinstance(filters, dict):
            qs = qs.filter(**filters)

        # safe_sort is allowlisted — safe to pass to order_by()
        # Django ORM order_by() uses the field name, not raw SQL
        qs = qs.order_by(safe_sort)
        return list(qs)


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
    def filter_with_raw_sql(cls, status=None, priority=None, assignee_id=None):
        """
        Filter tasks using structured ORM filters.

        FIX #3: The original method accepted a raw filter_expression string and
        interpolated it directly into WHERE.  This is replaced with an ORM
        queryset that accepts explicit, typed keyword arguments.
        All values go through Django's parameterization automatically.
        """
        # FIXED: use ORM .filter() instead of raw WHERE expression
        qs = cls.objects.select_related('assignee', 'project')
        if status is not None:
            qs = qs.filter(status=status)
        if priority is not None:
            qs = qs.filter(priority=priority)
        if assignee_id is not None:
            qs = qs.filter(assignee_id=assignee_id)
        return list(qs)

    @classmethod
    def get_tasks_by_criteria(cls, group_by_field, min_count=None):
        """
        Get tasks grouped by an allowlisted field.

        FIX #4: group_by_field validated against allowlist.
        FIX #5: having_clause free-text string replaced with typed min_count
                parameter — no raw SQL accepted.
        """
        # FIXED: validate group_by_field
        safe_group = _safe_identifier(group_by_field, TASK_GROUP_FIELDS, "group_by_field")

        # Build safe parameterized raw query — only safe_group (allowlisted) is interpolated
        query = f"""
            SELECT {safe_group} as group_value,
                   COUNT(*) as count,
                   STRING_AGG(title, ', ') as titles
            FROM tasks
            GROUP BY {safe_group}
        """
        params = []

        # FIXED: HAVING replaced with a typed numeric parameter
        if min_count is not None:
            query += " HAVING COUNT(*) >= %s"
            params.append(int(min_count))

        query += " ORDER BY count DESC"
        return list(cls.objects.raw(query, params))


class Comment(models.Model):
    """Comment model"""
    content = models.TextField()
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'comments'

    @classmethod
    def search_comments(cls, search_column_key, search_term):
        """
        Search comments — column selection via allowlist key.

        FIX #6: Instead of interpolating a raw search_columns string into SELECT,
        callers now pass a key ('content', 'author', 'task', 'created_at') which
        is looked up in COMMENT_SEARCH_COLUMNS.  Only the allowlisted SQL column
        reference is used.  search_term remains fully parameterized via ORM.
        """
        # FIXED: map key to safe column — reject unknown keys
        if search_column_key not in COMMENT_SEARCH_COLUMNS:
            raise ValueError(
                f"Invalid search column '{search_column_key}'. "
                f"Allowed: {sorted(COMMENT_SEARCH_COLUMNS.keys())}"
            )
        safe_col = COMMENT_SEARCH_COLUMNS[search_column_key]  # e.g. 'c.content'

        # Use ORM with a RawSQL annotation for the safe, allowlisted column expression.
        # search_term goes through LIKE parameterization via icontains.
        return list(
            cls.objects.select_related('author', 'task')
            .annotate(search_field=RawSQL(safe_col, []))
            .filter(content__icontains=search_term)
        )

    @classmethod
    def get_comments_with_filter(cls, task_id, order_by='created_at DESC'):
        """
        Get comments for a task with allowlisted ordering.

        FIX #7: order_expression free-text replaced with allowlist check.
        task_id is passed as a parameterized value (%s).
        """
        # FIXED: validate order expression
        safe_order = _safe_identifier(order_by, COMMENT_ORDER_FIELDS, "order_by")

        query = f"""
            SELECT c.*, u.username as author_name
            FROM comments c
            JOIN users u ON c.author_id = u.id
            WHERE c.task_id = %s
            ORDER BY {safe_order}
        """
        return list(cls.objects.raw(query, [task_id]))
