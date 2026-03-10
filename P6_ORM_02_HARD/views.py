"""
Views - Request handlers using vulnerable models and query builder
"""

from models import Project, Task, User, Comment
from query_builder import (
    ProjectQueryBuilder, 
    TaskAggregator,
    complex_project_search,
    get_user_dashboard_stats
)
from validators import (
    validate_field_name,
    validate_length,
    sanitize_sql_keywords
)


@validate_field_name
def handle_project_search(request):
    """
    Handle project search by dynamic field
    Uses INJECTION POINT #1
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
    except Exception as e:
        return {"error": str(e)}


@validate_length(max_length=200)
@sanitize_sql_keywords
def handle_project_stats(request):
    """
    Handle project statistics with sorting
    Uses INJECTION POINT #2
    """
    sort = request.GET.get('sort', 'name')
    filters = request.GET.get('filters', None)
    
    try:
        projects = Project.get_projects_with_stats(sort, filters)
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
    except Exception as e:
        return {"error": str(e)}


def handle_task_filter(request):
    """
    Handle task filtering with raw SQL
    Uses INJECTION POINT #3
    """
    filter_expr = request.GET.get('filter', '')
    
    if not filter_expr:
        return {"error": "Filter expression required"}
    
    try:
        tasks = Task.filter_with_raw_sql(filter_expr)
        return {
            "status": "success",
            "filter": filter_expr,
            "tasks": [
                {
                    "id": t.id,
                    "title": t.title,
                    "assignee": getattr(t, 'assignee_name', None)
                }
                for t in tasks
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_task_grouping(request):
    """
    Handle task grouping with HAVING
    Uses INJECTION POINTS #4 and #5
    """
    group_by = request.GET.get('group_by', 'status')
    having = request.GET.get('having', None)
    
    try:
        results = Task.get_tasks_by_criteria(group_by, having)
        return {
            "status": "success",
            "grouped_by": group_by,
            "having_clause": having,
            "results": [
                {
                    "group": getattr(r, group_by.split('.')[-1], None),
                    "count": r.count,
                    "titles": r.titles
                }
                for r in results
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_comment_search(request):
    """
    Handle comment search with dynamic columns
    Uses INJECTION POINT #6
    """
    columns = request.GET.get('columns', 'c.content')
    search_term = request.GET.get('term', '')
    
    if not search_term:
        return {"error": "Search term required"}
    
    try:
        comments = Comment.search_comments(columns, search_term)
        return {
            "status": "success",
            "search_columns": columns,
            "term": search_term,
            "comments": [
                {
                    "id": c.id,
                    "content": c.content[:100],
                    "author": getattr(c, 'author_name', None)
                }
                for c in comments
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_comment_ordering(request):
    """
    Handle comment retrieval with custom ordering
    Uses INJECTION POINT #7
    """
    task_id = request.GET.get('task_id', '')
    order = request.GET.get('order', 'created_at DESC')
    
    if not task_id:
        return {"error": "Task ID required"}
    
    try:
        comments = Comment.get_comments_with_filter(task_id, order)
        return {
            "status": "success",
            "task_id": task_id,
            "order_by": order,
            "comments": [
                {
                    "id": c.id,
                    "content": c.content,
                    "author": getattr(c, 'author_name', None)
                }
                for c in comments
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_complex_query(request):
    """
    Handle complex query using builder pattern
    Uses INJECTION POINTS #8, #9, #10
    """
    search_params = {
        'select_fields': request.GET.getlist('select'),
        'where_conditions': request.GET.getlist('where'),
        'group_by': request.GET.get('group_by'),
        'having': request.GET.get('having'),
        'order_by': request.GET.get('order_by')
    }
    
    try:
        projects = complex_project_search(search_params)
        return {
            "status": "success",
            "params": search_params,
            "count": len(projects),
            "projects": [
                {"id": p.id, "name": p.name}
                for p in projects
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_user_dashboard(request):
    """
    Handle user dashboard statistics
    Combines multiple models with dynamic stat field
    """
    user_id = request.GET.get('user_id', '')
    stat_field = request.GET.get('stat_field', 'u.role')
    filter_clause = request.GET.get('filter', '1=1')
    
    if not user_id:
        return {"error": "User ID required"}
    
    try:
        stats = get_user_dashboard_stats(user_id, stat_field, filter_clause)
        return {
            "status": "success",
            "user_id": user_id,
            "stats": [
                {
                    "username": row[0],
                    "department": row[1],
                    "stat_value": row[2],
                    "project_count": row[3],
                    "task_count": row[4]
                }
                for row in stats
            ]
        }
    except Exception as e:
        return {"error": str(e)}


# Mock request class
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
