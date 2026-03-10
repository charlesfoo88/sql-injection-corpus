"""
Views - Request handlers
REMEDIATED: Updated to use fixed model/builder APIs.

Key changes per handler:
- handle_project_search     : passes field as allowlisted key (not raw string)
- handle_project_stats      : passes sort as allowlisted key; filters as ORM dict
- handle_task_filter        : passes typed kwargs instead of raw filter expression
- handle_task_grouping      : passes group_by key + typed min_count integer
- handle_comment_search     : passes column key instead of raw column expression
- handle_comment_ordering   : passes allowlisted order string
- handle_complex_query      : uses where_kwargs + typed params (no raw SQL strings)
- handle_user_dashboard     : passes stat_field key + ORM filter kwargs

Removed imports of the false-security validators (validate_field_name,
sanitize_sql_keywords) — real security is now in the model/builder layer.
"""

from models import Project, Task, User, Comment
from query_builder import (
    ProjectQueryBuilder,
    TaskAggregator,
    complex_project_search,
    get_user_dashboard_stats,
)


def handle_project_search(request):
    """
    Handle project search by dynamic field.
    FIX: field value is an allowlisted key — not interpolated directly.
    """
    field = request.GET.get('field', 'name')
    value = request.GET.get('value', '')

    if not value:
        return {"error": "Value required"}

    try:
        projects = Project.search_by_criteria(field, value)
        return {
            "status": "success",
            "search_field": field,
            "results": [
                {"id": p.id, "name": p.name, "status": p.status}
                for p in projects
            ]
        }
    except (ValueError, TypeError) as e:
        return {"error": str(e)}


def handle_project_stats(request):
    """
    Handle project statistics with sorting.
    FIX: sort is allowlist-validated in the model; filters is a dict, not raw SQL.
    """
    sort = request.GET.get('sort', 'name')
    # filters must now be passed as a JSON-decodable dict by the caller,
    # e.g. {"status": "active"}.  Raw SQL filter strings are rejected.
    raw_filters = request.GET.get('filters', None)
    filters_dict = None
    if raw_filters:
        import json
        try:
            filters_dict = json.loads(raw_filters)
            if not isinstance(filters_dict, dict):
                return {"error": "filters must be a JSON object"}
        except json.JSONDecodeError:
            return {"error": "filters must be valid JSON"}

    try:
        projects = Project.get_projects_with_stats(sort, filters_dict)
        return {
            "status": "success",
            "sort_by": sort,
            "projects": [
                {
                    "id": p.id,
                    "name": p.name,
                    "task_count": getattr(p, 'task_count', 0)
                }
                for p in projects
            ]
        }
    except (ValueError, TypeError) as e:
        return {"error": str(e)}


def handle_task_filter(request):
    """
    Handle task filtering.
    FIX: raw filter_expression replaced with explicit typed query params.
    """
    status = request.GET.get('status') or None
    priority_raw = request.GET.get('priority') or None
    assignee_id_raw = request.GET.get('assignee_id') or None

    priority = None
    if priority_raw is not None:
        try:
            priority = int(priority_raw)
        except ValueError:
            return {"error": "priority must be an integer"}

    assignee_id = None
    if assignee_id_raw is not None:
        try:
            assignee_id = int(assignee_id_raw)
        except ValueError:
            return {"error": "assignee_id must be an integer"}

    try:
        tasks = Task.filter_with_raw_sql(
            status=status,
            priority=priority,
            assignee_id=assignee_id,
        )
        return {
            "status": "success",
            "tasks": [
                {
                    "id": t.id,
                    "title": t.title,
                    "assignee": getattr(t, 'assignee_id', None),
                }
                for t in tasks
            ]
        }
    except (ValueError, TypeError) as e:
        return {"error": str(e)}


def handle_task_grouping(request):
    """
    Handle task grouping.
    FIX: group_by validated via allowlist; having_clause replaced with typed min_count.
    """
    group_by = request.GET.get('group_by', 'status')
    min_count_raw = request.GET.get('min_count') or None

    min_count = None
    if min_count_raw is not None:
        try:
            min_count = int(min_count_raw)
        except ValueError:
            return {"error": "min_count must be an integer"}

    try:
        results = Task.get_tasks_by_criteria(group_by, min_count)
        return {
            "status": "success",
            "grouped_by": group_by,
            "min_count": min_count,
            "results": [
                {
                    "group": getattr(r, 'group_value', None),
                    "count": r.count,
                    "titles": r.titles,
                }
                for r in results
            ]
        }
    except (ValueError, TypeError) as e:
        return {"error": str(e)}


def handle_comment_search(request):
    """
    Handle comment search.
    FIX: columns is now a key looked up in COMMENT_SEARCH_COLUMNS allowlist.
    """
    column_key = request.GET.get('column', 'content')
    search_term = request.GET.get('term', '')

    if not search_term:
        return {"error": "Search term required"}

    try:
        comments = Comment.search_comments(column_key, search_term)
        return {
            "status": "success",
            "search_column": column_key,
            "term": search_term,
            "comments": [
                {
                    "id": c.id,
                    "content": c.content[:100],
                    "author": getattr(c, 'author_id', None),
                }
                for c in comments
            ]
        }
    except (ValueError, TypeError) as e:
        return {"error": str(e)}


def handle_comment_ordering(request):
    """
    Handle comment retrieval with ordering.
    FIX: order is validated against COMMENT_ORDER_FIELDS allowlist in the model.
    """
    task_id = request.GET.get('task_id', '')
    order = request.GET.get('order', 'created_at DESC')

    if not task_id:
        return {"error": "Task ID required"}

    try:
        task_id_int = int(task_id)
    except ValueError:
        return {"error": "task_id must be an integer"}

    try:
        comments = Comment.get_comments_with_filter(task_id_int, order)
        return {
            "status": "success",
            "task_id": task_id_int,
            "order_by": order,
            "comments": [
                {
                    "id": c.id,
                    "content": c.content,
                    "author": getattr(c, 'author_name', None),
                }
                for c in comments
            ]
        }
    except (ValueError, TypeError) as e:
        return {"error": str(e)}


def handle_complex_query(request):
    """
    Handle complex query using builder pattern.
    FIX: where conditions passed as ORM kwargs dict, not raw SQL strings.
         select and order validated via allowlists in the builder.
    """
    select_fields = request.GET.getlist('select')
    order_by = request.GET.get('order_by') or None
    min_task_count_raw = request.GET.get('min_task_count') or None

    # Parse WHERE as JSON dict  e.g. ?where={"status":"active","priority":2}
    import json
    where_kwargs = {}
    raw_where = request.GET.get('where') or None
    if raw_where:
        try:
            where_kwargs = json.loads(raw_where)
            if not isinstance(where_kwargs, dict):
                return {"error": "where must be a JSON object"}
        except json.JSONDecodeError:
            return {"error": "where must be valid JSON"}

    min_task_count = None
    if min_task_count_raw is not None:
        try:
            min_task_count = int(min_task_count_raw)
        except ValueError:
            return {"error": "min_task_count must be an integer"}

    search_params = {
        'select_fields': select_fields,
        'where_kwargs': where_kwargs,
        'order_by': order_by,
    }
    if min_task_count is not None:
        search_params['min_task_count'] = min_task_count

    try:
        projects = complex_project_search(search_params)
        return {
            "status": "success",
            "count": len(projects),
            "projects": [{"id": p.id, "name": p.name} for p in projects]
        }
    except (ValueError, TypeError) as e:
        return {"error": str(e)}


def handle_user_dashboard(request):
    """
    Handle user dashboard statistics.
    FIX: stat_field is an allowlisted key; filter_clause replaced with ORM kwargs.
    """
    user_id_raw = request.GET.get('user_id', '')
    stat_field_key = request.GET.get('stat_field', 'role')

    if not user_id_raw:
        return {"error": "User ID required"}

    try:
        user_id = int(user_id_raw)
    except ValueError:
        return {"error": "user_id must be an integer"}

    # Additional ORM-style filters (optional)
    import json
    extra_filters = {}
    raw_filter = request.GET.get('filter') or None
    if raw_filter:
        try:
            extra_filters = json.loads(raw_filter)
            if not isinstance(extra_filters, dict):
                return {"error": "filter must be a JSON object"}
        except json.JSONDecodeError:
            return {"error": "filter must be valid JSON"}

    try:
        stats = get_user_dashboard_stats(user_id, stat_field_key, **extra_filters)
        return {
            "status": "success",
            "user_id": user_id,
            "stats": [
                {
                    "username": row[0],
                    "department": row[1],
                    "stat_value": row[2],
                    "project_count": row[3],
                    "task_count": row[4],
                }
                for row in stats
            ]
        }
    except (ValueError, TypeError) as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Mock helpers (unchanged — used by test_exploit.py)
# ---------------------------------------------------------------------------

class MockRequest:
    def __init__(self, params):
        self.GET = MockGET(params)


class MockGET:
    def __init__(self, params):
        self.params = params

    def get(self, key, default=None):
        return self.params.get(key, default)

    def getlist(self, key):
        value = self.params.get(key, [])
        if isinstance(value, list):
            return value
        return [value] if value else []
