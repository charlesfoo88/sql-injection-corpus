"""
Analytics module for article CMS system.
Provides reporting and statistical analysis on article data.
"""

from django.db import models


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
    
    @classmethod
    def get_article_stats_by_field(cls, sort_field):
        """
        Get article statistics sorted by specified field.
        
        Args:
            sort_field: Database field name to sort results by
            
        Returns:
            QuerySet of articles sorted by the specified field
        """
        return cls.objects.all().extra(order_by=[sort_field])
    
    @classmethod
    def get_filtered_articles(cls, where_condition):
        """
        Get articles matching a custom WHERE condition.
        
        Args:
            where_condition: SQL WHERE clause fragment
            
        Returns:
            QuerySet of articles matching the condition
        """
        return cls.objects.all().extra(where=[where_condition])
    
    @classmethod
    def get_articles_with_computed_column(cls, column_name, expression):
        """
        Get articles with a dynamically computed column.
        
        Args:
            column_name: Name for the computed column
            expression: SQL expression to compute column value
            
        Returns:
            QuerySet with additional computed column
        """
        select_dict = {column_name: expression}
        return cls.objects.all().extra(select=select_dict)
    
    @classmethod
    def get_articles_with_extra_table(cls, extra_table, join_condition):
        """
        Get articles with data joined from an additional table.
        
        Args:
            extra_table: Name of table to join
            join_condition: SQL condition for the join
            
        Returns:
            QuerySet with data from joined table
        """
        return cls.objects.all().extra(
            tables=[extra_table],
            where=[join_condition]
        )


class ArticleStats(models.Model):
    """Article statistics aggregation model"""
    article = models.OneToOneField(Article, on_delete=models.CASCADE)
    total_views = models.IntegerField(default=0)
    unique_visitors = models.IntegerField(default=0)
    avg_read_time = models.FloatField(default=0.0)
    last_viewed = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'article_stats'
