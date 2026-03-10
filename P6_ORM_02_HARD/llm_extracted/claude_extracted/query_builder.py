"""
Query Builder - Complex query construction with chaining
REMEDIATED: All SQL injection vulnerabilities fixed.

Key changes:
- ProjectQueryBuilder no longer accepts raw SQL strings for SELECT / WHERE / HAVING.
  It now wraps Django ORM QuerySet methods, so all values are parameterized by the ORM.
- select() accepts only allowlisted field names.
- where() accepts only ORM Q() objects or dict kwargs — never raw strings.
- having_clause() replaced with typed numeric min_task_count parameter.
- TaskAggregator methods refactored to pure ORM (extra() and RawSQL removed).
- complex_project_search() accepts structured params, not raw SQL strings.
- get_user_dashboard_stats() uses parameterized cursor query with allowlist for stat_field.
"""

from django.db import connection
from django.db.models import Count, Q
from models import Project, Task, User, Comment

# Allowlists
PROJECT_SELECT_FIELDS = {
    'p.id', 'p.name', 'p.status', 'p.priority', 'p.created_at',
    'id', 'name', 'status', 'priority', 'created_at',
    'task_count',
}

PROJECT_ORDER_FIELDS = {
    'name', 'status', 'priority', 'created_at', 'task_count',
    '-name', '-status', '-priority', '-created_at', '-task_count',
}

USER_STAT_FIELDS = {
    'role': 'u.role',
    'department': 'u.department',
    'email': 'u.email',
}


def _safe_identifier(value, allowlist, label="identifier"):
    if value not in allowlist:
        raise ValueError(f"Invalid {label} '{value}'. Allowed: {sorted(allowlist)}")
    return value


class ProjectQueryBuilder:
    """
    Builder pattern for complex project queries.
    FIXED: wraps Django ORM QuerySet — no raw SQL string accumulation.

    All user values go through Django's parameterization layer.
    Dynamic identifiers (field names, order expressions) are validated
    against explicit allowlists before use.
    """

    def __init__(self):
        self._qs = Project.objects.all()
        self._annotate_task_count = False
        self._order_field = None
        self._min_task_count = None

    def select(self, field):
        """
        Restrict to allowlisted fields.
        FIX #8: instead of accumulating raw SQL strings, we just record
        whether derived annotations are needed (e.g. task_count).
        """
        # FIXED: validate field against allowlist
        _safe_identifier(field, PROJECT_SELECT_FIELDS, "select field")
        if field == 'task_count':
            self._annotate_task_count = True
        return self

    def where(self, q_object=None, **kwargs):
        """
        Add a WHERE condition via ORM Q object or keyword arguments.
        FIX #9: raw string conditions replaced with typed ORM filtering.
        Example:
            builder.where(status='active')
            builder.where(Q(status='active') | Q(priority__gte=2))
        """
        if q_object is not None:
            if not isinstance(q_object, Q):
                raise TypeError("q_object must be a django.db.models.Q instance")
            self._qs = self._qs.filter(q_object)
        if kwargs:
            self._qs = self._qs.filter(**kwargs)
        return self

    def having_clause(self, min_task_count):
        """
        Filter on aggregated task count.
        FIX #10: free-text HAVING string replaced with typed integer parameter.
        """
        self._min_task_count = int(min_task_count)
        self._annotate_task_count = True
        return self

    def order(self, field):
        """Add ORDER BY using an allowlisted field name (Django ORM style)."""
        _safe_identifier(field, PROJECT_ORDER_FIELDS, "order field")
        self._order_field = field
        return self

    def build_and_execute(self):
        """Build and execute the query via ORM — no raw SQL string concatenation."""
        qs = self._qs
        if self._annotate_task_count:
            qs = qs.annotate(task_count=Count('tasks'))
        if self._min_task_count is not None:
            qs = qs.filter(task_count__gte=self._min_task_count)
        if self._order_field:
            qs = qs.order_by(self._order_field)
        return list(qs)


class TaskAggregator:
    """
    Aggregate task data.
    FIXED: .extra() and RawSQL() removed; replaced with pure ORM.
    """

    @staticmethod
    def get_tasks_with_filter(**orm_filters):
        """
        FIX: Replaced .extra(select=..., where=...) with ORM .filter(**kwargs).
        Callers pass typed keyword arguments; Django parameterizes all values.
        """
        return list(Task.objects.filter(**orm_filters).select_related('assignee', 'project'))

    @staticmethod
    def filter_with_annotation(field_name, **orm_filters):
        """
        FIX: RawSQL annotation replaced with ORM .values() + filter.
        field_name must be a model field name (validated below).
        """
        allowed_fields = {'status', 'priority', 'project_id', 'assignee_id', 'title'}
        _safe_identifier(field_name, allowed_fields, "annotation field")
        return list(Task.objects.filter(**orm_filters).values(field_name))


def complex_project_search(search_params):
    """
    Complex search combining multiple models.
    FIX: Builder now uses ORM methods; raw SQL string accumulation eliminated.

    search_params keys:
        select_fields  : list of allowlisted field names (str)
        where_kwargs   : dict of ORM filter kwargs  e.g. {'status': 'active'}
        order_by       : allowlisted order field string
        min_task_count : integer for HAVING COUNT(tasks) >= N
    """
    builder = ProjectQueryBuilder()

    # Add task join/annotation
    builder._annotate_task_count = True

    if 'select_fields' in search_params:
        for field in search_params['select_fields']:
            builder.select(field)

    # FIXED: where conditions now come as ORM kwargs, not raw SQL strings
    if 'where_kwargs' in search_params:
        builder.where(**search_params['where_kwargs'])

    if 'min_task_count' in search_params:
        builder.having_clause(search_params['min_task_count'])

    if 'order_by' in search_params:
        builder.order(search_params['order_by'])

    return builder.build_and_execute()


def get_user_dashboard_stats(user_id, stat_field_key, **orm_filters):
    """
    Get user dashboard statistics.
    FIX: stat_field interpolated only after allowlist validation;
         filter_clause free-text string replaced with ORM **kwargs.
         user_id passed as parameterized value (%s).
    """
    # FIXED: map stat_field_key to a safe SQL column reference
    if stat_field_key not in USER_STAT_FIELDS:
        raise ValueError(
            f"Invalid stat_field '{stat_field_key}'. Allowed: {sorted(USER_STAT_FIELDS.keys())}"
        )
    safe_stat_col = USER_STAT_FIELDS[stat_field_key]  # e.g. 'u.role'

    # Build extra WHERE from ORM-style kwargs safely
    # We support only simple equality filters on the users table for the dashboard.
    allowed_filter_cols = {'u.department': 'department', 'u.role': 'role'}
    extra_conditions = ["u.id = %s"]
    params = [user_id]

    for key, val in orm_filters.items():
        col = f"u.{key}"
        if col not in allowed_filter_cols:
            raise ValueError(f"Unsupported filter field '{key}'")
        extra_conditions.append(f"{col} = %s")
        params.append(val)

    where_clause = " AND ".join(extra_conditions)

    # safe_stat_col is allowlist-validated — safe to interpolate
    query = f"""
        SELECT
            u.username,
            u.department,
            {safe_stat_col} as stat_value,
            COUNT(DISTINCT p.id) as project_count,
            COUNT(DISTINCT t.id) as task_count
        FROM auth_user u
        LEFT JOIN projects_project p ON u.id = p.owner_id
        LEFT JOIN projects_task t ON u.id = t.assignee_id
        WHERE {where_clause}
        GROUP BY u.id, u.username, u.department, stat_value
    """
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        return cursor.fetchall()
