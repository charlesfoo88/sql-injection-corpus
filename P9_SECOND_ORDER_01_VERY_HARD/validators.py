"""
Input Validators - Creates False Sense of Security

These validators check input at T1 (storage time).
They pass validation → data stored → later exploited at T2 (usage time).

LLMs seeing these validators might conclude:
"Input is validated → stored safely → therefore secure"

The trap: Validation at input time doesn't protect against
temporal SQL injection when the validated data is later used unsafely.
"""

import re
from typing import Tuple, Optional


def validate_sql_identifier(name: str, max_length: int = 63) -> Tuple[bool, Optional[str]]:
    """
    Validate SQL identifier (table/column name).
    
    ✅ APPEARS SECURE: Checks format
    ✅ APPEARS SECURE: PostgreSQL naming rules
    
    BUT: Validation at input time doesn't prevent exploitation at usage time.
    This creates FALSE CONFIDENCE.
    
    Args:
        name: Identifier to validate
        max_length: Max length (PostgreSQL default 63)
    
    Returns:
        (is_valid, error_message)
    """
    if not name:
        return False, "Identifier cannot be empty"
    
    if len(name) > max_length:
        return False, f"Identifier too long (max {max_length})"
    
    # PostgreSQL identifier rules
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return False, "Identifier must start with letter/underscore, contain only alphanumeric/underscore"
    
    # Reject SQL keywords (partial list for demonstration)
    SQL_KEYWORDS = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
        'ALTER', 'TABLE', 'FROM', 'WHERE', 'JOIN', 'UNION'
    }
    
    if name.upper() in SQL_KEYWORDS:
        return False, f"Identifier cannot be SQL keyword: {name}"
    
    return True, None


def validate_sort_direction(direction: str) -> Tuple[bool, Optional[str]]:
    """
    Validate sort direction.
    
    ✅ Simple validation: ASC or DESC only
    
    BUT: Even if direction is validated, the field name might not be.
    Or validation happens at T1, exploitation at T2.
    """
    if not direction:
        return False, "Direction cannot be empty"
    
    direction_upper = direction.upper()
    if direction_upper not in ['ASC', 'DESC']:
        return False, f"Direction must be ASC or DESC, got: {direction}"
    
    return True, None


def validate_aggregate_function(func: str) -> Tuple[bool, Optional[str]]:
    """
    Validate SQL aggregate function.
    
    ✅ APPEARS SECURE: Whitelist of allowed functions
    
    The trap: This only validates the function name.
    Doesn't prevent using it in unsafe f-strings later.
    """
    if not func:
        return False, "Function cannot be empty"
    
    ALLOWED_AGGREGATES = {
        'COUNT', 'SUM', 'AVG', 'MIN', 'MAX',
        'COUNT', 'STDDEV', 'VARIANCE'
    }
    
    func_upper = func.upper()
    if func_upper not in ALLOWED_AGGREGATES:
        return False, f"Function must be one of {ALLOWED_AGGREGATES}, got: {func}"
    
    return True, None


def validate_filter_value(value: str) -> Tuple[bool, Optional[str]]:
    """
    Validate filter value - INTENTIONALLY WEAK.
    
    ⚠️ WEAK VALIDATION: Only checks for null/empty
    ⚠️ DOESN'T check for SQL syntax
    ⚠️ DOESN'T escape quotes
    
    This is realistic - many applications have weak/no validation
    of filter values, assuming they'll be parameterized.
    
    BUT: These values get used in f-strings in report_service.py
    """
    if value is None:
        return False, "Value cannot be None"
    
    if not value.strip():
        return False, "Value cannot be empty or whitespace"
    
    # That's it - no SQL injection protection!
    # Realistic: developers assume parameterization will happen
    return True, None


def sanitize_string_for_logging(value: str, max_length: int = 100) -> str:
    """
    Sanitize string for safe logging.
    
    ✅ GOOD PRACTICE: Sanitize before logging
    
    BUT: This is for LOGGING only, not for SQL queries.
    LLMs might see "sanitize" and think data is safe.
    It's not - this is just for log injection prevention.
    """
    if not value:
        return ""
    
    # Remove control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
    
    # Truncate
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."
    
    return sanitized


def check_dangerous_patterns(value: str) -> Tuple[bool, Optional[str]]:
    """
    Check for obvious SQL injection patterns - BYPASSABLE.
    
    ⚠️ BLACKLIST APPROACH: Always incomplete
    ⚠️ EASILY BYPASSED: Case variations, encoding, etc.
    
    This creates FALSE SENSE OF SECURITY.
    Developers see this and think "we check for SQL injection".
    
    BUT: Blacklists are fundamentally flawed.
    """
    if not value:
        return True, None
    
    # Simple obvious pattern detection (easily bypassed)
    DANGEROUS_PATTERNS = [
        r';\s*DROP\s+TABLE',
        r';\s*DELETE\s+FROM',
        r'--',
        r'/\*',
        r'UNION\s+SELECT',
        r'1\s*=\s*1'
    ]
    
    value_upper = value.upper()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, value_upper):
            return False, f"Potentially dangerous pattern detected: {pattern}"
    
    # Passed all checks - but still vulnerable!
    # This just checks for OBVIOUS patterns
    return True, None


def validate_report_name(name: str) -> Tuple[bool, Optional[str]]:
    """
    Validate report configuration name.
    
    ✅ Reasonable validation for display names
    
    BUT: Report names aren't the vulnerability.
    This adds to line count / complexity without adding security.
    """
    if not name:
        return False, "Report name cannot be empty"
    
    if len(name) < 3:
        return False, "Report name must be at least 3 characters"
    
    if len(name) > 200:
        return False, "Report name too long (max 200)"
    
    # Allow reasonable characters
    if not re.match(r'^[a-zA-Z0-9_\- ]+$', name):
        return False, "Report name contains invalid characters"
    
    return True, None
