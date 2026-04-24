"""
Analytics module for article CMS system.
Provides reporting and statistical analysis on article data.
"""

from django.db import models
from django.core.exceptions import ValidationError


class Author(models.Model):
    """Author model for CMS users"""
    name = models.CharField(max_length=100)
    email = models.EmailField()
    bio = models.TextField(blank=True)
    
    class Meta:
        db_table = 'authors'


class Category(models.Model):
    """Category model for article classification"""
    name = models.CharField(max_length=50)
    description = models.TextField(blank=True)
    
    class Meta:
        db_table = 'categories'


class Article(models.Model):
    """Article model for CMS content"""
    title = models.CharField(max_length=200)
    content = models.TextField()
    author = models.ForeignKey(Author, on_delete=models.CASCADE)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    tags = models.CharField(max_length=200)
    published_date = models.DateField()
    views = models.IntegerField(default=0)
    likes = models.IntegerField(default=0)
    is_featured = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'articles'
    
    # Whitelist of allowed sort fields
    ALLOWED_SORT_FIELDS = {
        'title', 'published_date', 'views', 'likes', 'is_featured',
        '-title', '-published_date', '-views', '-likes', '-is_featured',
        'author__name', 'category__name', '-author__name', '-category__name'
    }
    
    @classmethod
    def get_article_stats_by_field(cls, sort_field):
        """
        Get article statistics sorted by specified field.
        
        Args:
            sort_field: Database field name to sort results by (must be whitelisted)
            
        Returns:
            QuerySet of articles sorted by the specified field
            
        Raises:
            ValidationError: If sort_field is not in allowed list
        """
        if sort_field not in cls.ALLOWED_SORT_FIELDS:
            raise ValidationError(f"Invalid sort field: {sort_field}")
        
        return cls.objects.all().order_by(sort_field)
    
    @classmethod
    def get_filtered_articles(cls, **filters):
        """
        Get articles matching specified filters using Django ORM.
        
        Args:
            **filters: Keyword arguments for Django ORM filtering
                      (e.g., views__gte=100, is_featured=True)
            
        Returns:
            QuerySet of articles matching the filters
        """
        return cls.objects.filter(**filters)
    
    @classmethod
    def get_articles_with_computed_column(cls, computation_type, **kwargs):
        """
        Get articles with a dynamically computed column using safe aggregations.
        
        Args:
            computation_type: Type of computation ('engagement_score', 'view_like_ratio', etc.)
            **kwargs: Additional parameters for specific computations
            
        Returns:
            QuerySet with additional computed column using Django annotations
        """
        from django.db.models import F, Value, FloatField, ExpressionWrapper
        from django.db.models.functions import Cast, Coalesce
        
        if computation_type == 'engagement_score':
            # Safe computation: views + (likes * weight)
            weight = kwargs.get('like_weight', 2)
            return cls.objects.annotate(
                engagement_score=ExpressionWrapper(
                    F('views') + (F('likes') * weight),
                    output_field=FloatField()
                )
            )
        elif computation_type == 'view_like_ratio':
            # Safe computation: likes / views (handling division by zero)
            return cls.objects.annotate(
                view_like_ratio=ExpressionWrapper(
                    Cast(F('likes'), FloatField()) / Coalesce(F('views'), Value(1)),
                    output_field=FloatField()
                )
            )
        elif computation_type == 'popularity_index':
            # Safe computation: weighted combination of metrics
            view_weight = kwargs.get('view_weight', 1.0)
            like_weight = kwargs.get('like_weight', 2.0)
            featured_bonus = kwargs.get('featured_bonus', 100)
            
            return cls.objects.annotate(
                popularity_index=ExpressionWrapper(
                    (F('views') * view_weight) + 
                    (F('likes') * like_weight) + 
                    (F('is_featured') * featured_bonus),
                    output_field=FloatField()
                )
            )
        else:
            raise ValidationError(f"Invalid computation type: {computation_type}")
    
    @classmethod
    def get_articles_with_extra_table(cls, relation_type, **filters):
        """
        Get articles with data from related tables using Django ORM joins.
        
        Args:
            relation_type: Type of relation to include ('author_details', 'category_details', 'stats')
            **filters: Additional filters to apply
            
        Returns:
            QuerySet with data from related tables using select_related/prefetch_related
        """
        queryset = cls.objects.all()
        
        if relation_type == 'author_details':
            queryset = queryset.select_related('author')
            if filters:
                queryset = queryset.filter(**{f'author__{k}': v for k, v in filters.items()})
        
        elif relation_type == 'category_details':
            queryset = queryset.select_related('category')
            if filters:
                queryset = queryset.filter(**{f'category__{k}': v for k, v in filters.items()})
        
        elif relation_type == 'stats':
            queryset = queryset.select_related('articlestats')
            if filters:
                queryset = queryset.filter(**{f'articlestats__{k}': v for k, v in filters.items()})
        
        elif relation_type == 'all_relations':
            queryset = queryset.select_related('author', 'category', 'articlestats')
            if filters:
                queryset = queryset.filter(**filters)
        
        else:
            raise ValidationError(f"Invalid relation type: {relation_type}")
        
        return queryset


class ArticleStats(models.Model):
    """Article statistics aggregation model"""
    article = models.OneToOneField(Article, on_delete=models.CASCADE)
    total_views = models.IntegerField(default=0)
    unique_visitors = models.IntegerField(default=0)
    avg_read_time = models.FloatField(default=0.0)
    last_viewed = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'article_stats'