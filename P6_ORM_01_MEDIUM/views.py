"""
Blog Article Views - Handler Functions
Calls vulnerable model methods with user input
"""

from models import Article, ArticleStats


def handle_category_search(request):
    """
    Handle category search requests
    Uses INJECTION POINT #1: search_by_category
    """
    category = request.GET.get('category', '')
    
    if not category:
        return {"error": "Category parameter required"}
    
    try:
        articles = Article.search_by_category(category)
        return {
            "status": "success",
            "count": len(articles),
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    "author": a.author,
                    "category": a.category
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_author_filter(request):
    """
    Handle author filter requests
    Uses INJECTION POINT #2: filter_by_author
    """
    author = request.GET.get('author', '')
    
    if not author:
        return {"error": "Author parameter required"}
    
    try:
        articles = Article.filter_by_author(author)
        return {
            "status": "success",
            "author": author,
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    "published_date": str(a.published_date)
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_article_sort(request):
    """
    Handle article sorting requests
    Uses INJECTION POINT #3: sort_articles
    """
    sort_field = request.GET.get('sort', 'published_date')
    order = request.GET.get('order', 'DESC')
    
    try:
        articles = Article.sort_articles(sort_field, order)
        return {
            "status": "success",
            "sort_by": sort_field,
            "order": order,
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    f"{sort_field}": getattr(a, sort_field, None)
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_tag_search(request):
    """
    Handle tag search requests
    Uses INJECTION POINT #4: search_by_tag
    """
    tag = request.GET.get('tag', '')
    
    if not tag:
        return {"error": "Tag parameter required"}
    
    try:
        articles = Article.search_by_tag(tag)
        return {
            "status": "success",
            "tag": tag,
            "count": len(articles),
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    "tags": a.tags
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_custom_columns(request):
    """
    Handle custom column selection requests
    Uses INJECTION POINT #5: get_articles_with_columns
    """
    columns = request.GET.get('columns', '*')
    
    try:
        articles = Article.get_articles_with_columns(columns)
        return {
            "status": "success",
            "columns": columns,
            "count": len(articles),
            "data": [
                {attr: getattr(a, attr, None) for attr in dir(a) if not attr.startswith('_')}
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_date_filter(request):
    """
    Handle date range filter requests
    Uses INJECTION POINT #6: filter_by_date_range
    """
    date_from = request.GET.get('from', '')
    date_to = request.GET.get('to', '')
    
    if not date_from or not date_to:
        return {"error": "Both 'from' and 'to' date parameters required"}
    
    try:
        articles = Article.filter_by_date_range(date_from, date_to)
        return {
            "status": "success",
            "date_range": f"{date_from} to {date_to}",
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    "published_date": str(a.published_date)
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_statistics(request):
    """
    Handle statistics requests (SAFE - uses parameterized queries)
    """
    stat_type = request.GET.get('type', 'authors')
    
    if stat_type == 'authors':
        limit = int(request.GET.get('limit', 10))
        results = ArticleStats.get_top_authors(limit)
        return {
            "status": "success",
            "type": "top_authors",
            "data": [
                {"author": row[0], "article_count": row[1]}
                for row in results
            ]
        }
    elif stat_type == 'categories':
        results = ArticleStats.get_category_stats()
        return {
            "status": "success",
            "type": "category_stats",
            "data": [
                {"category": row[0], "count": row[1], "avg_views": float(row[2])}
                for row in results
            ]
        }
    else:
        return {"error": "Invalid statistics type"}


# Mock request class for testing
class MockRequest:
    def __init__(self, params):
        self.GET = params
