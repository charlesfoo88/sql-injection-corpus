"""
Validators - False security layer
These validators appear to provide security but are insufficient
"""

import re
from functools import wraps


def validate_field_name(func):
    """
    Decorator to validate field names
    FALSE SECURITY: Only checks alphanumeric + underscore
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check if any argument looks like a field name
        for arg in args:
            if isinstance(arg, str) and len(arg) > 0:
                # Weak validation: allows underscores and dots
                if not re.match(r'^[a-zA-Z0-9_.]+$', arg):
                    raise ValueError(f"Invalid field name: {arg}")
        return func(*args, **kwargs)
    return wrapper


def validate_length(max_length=100):
    """
    Decorator to validate string length
    FALSE SECURITY: Length check doesn't prevent SQL injection
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for arg in args:
                if isinstance(arg, str) and len(arg) > max_length:
                    raise ValueError(f"Input too long (max {max_length})")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_type(expected_type):
    """
    Decorator to validate argument type
    FALSE SECURITY: Type check doesn't validate content
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for arg in args:
                if arg is not None and not isinstance(arg, expected_type):
                    raise TypeError(f"Expected {expected_type}, got {type(arg)}")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def sanitize_sql_keywords(func):
    """
    Decorator to check for SQL keywords
    FALSE SECURITY: Blacklist approach is bypassable
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Blacklist of "dangerous" keywords (incomplete)
        blacklist = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'EXEC', 'EXECUTE']
        
        for arg in args:
            if isinstance(arg, str):
                upper_arg = arg.upper()
                for keyword in blacklist:
                    if keyword in upper_arg:
                        raise ValueError(f"Forbidden keyword detected: {keyword}")
        
        return func(*args, **kwargs)
    return wrapper


def validate_sql_expression(expression):
    """
    Validate SQL expression (inadequate)
    FALSE SECURITY: Regex pattern matching is insufficient
    """
    # Pattern checks for basic SQL expression
    # But doesn't prevent injection
    patterns = [
        r'^[a-zA-Z0-9_\s\.\,\(\)]+$',  # Alphanumeric with basic SQL chars
        r'^COUNT\([a-zA-Z0-9_\.]+\)$',  # COUNT function
        r'^[a-zA-Z0-9_]+\s+(ASC|DESC)$',  # ORDER BY
    ]
    
    for pattern in patterns:
        if re.match(pattern, expression):
            return True
    
    # If no pattern matches, still allow (weak!)
    return True


def check_parameter_count(expected_count):
    """
    Check number of parameters
    FALSE SECURITY: Count check doesn't validate content
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            actual_count = len(args) + len(kwargs)
            if actual_count != expected_count:
                raise ValueError(f"Expected {expected_count} parameters, got {actual_count}")
            return func(*args, **kwargs)
        return wrapper
    return decorator


class InputValidator:
    """
    Input validation class
    Provides various validation methods that appear secure but aren't
    """
    
    @staticmethod
    def is_safe_identifier(identifier):
        """
        Check if identifier is safe
        FALSE SECURITY: Only checks format, not content
        """
        return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', identifier))
    
    @staticmethod
    def is_safe_expression(expression):
        """
        Check if expression is safe
        FALSE SECURITY: Whitelist approach but too permissive
        """
        # Allows too many characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.,()[] ')
        return all(c in allowed_chars for c in expression)
    
    @staticmethod
    def sanitize_quotes(value):
        """
        Escape quotes
        FALSE SECURITY: Insufficient for proper SQL escaping
        """
        # Simple quote escaping - inadequate
        return value.replace("'", "''")
    
    @staticmethod
    def validate_date_format(date_str):
        """
        Validate date format
        FALSE SECURITY: Format validation doesn't prevent injection after valid date
        """
        pattern = r'^\d{4}-\d{2}-\d{2}$'
        return bool(re.match(pattern, date_str))
