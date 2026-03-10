"""Preference Service - SECURE VERSION with execution-time validation

SECURITY IMPROVEMENTS:
1. Execution-time validation of all retrieved preferences
2. Strict allowlist enforcement at multiple layers
3. Comprehensive input sanitization
4. Defense-in-depth approach
"""

from models.user_preference import UserPreference
from typing import Optional, Dict, Any
import re

# Allowed field names for validation - IMMUTABLE ALLOWLISTS
ALLOWED_SORT_FIELDS = frozenset({
    'id', 'username', 'email', 'created_at', 'last_login',
    'status', 'role', 'department', 'salary', 'age'
})

ALLOWED_FILTER_FIELDS = frozenset({
    'status', 'role', 'department', 'country', 'city', 
    'account_type', 'subscription_level'
})

ALLOWED_GROUP_FIELDS = frozenset({
    'department', 'role', 'country', 'city', 'status'
})

ALLOWED_AGGREGATES = frozenset({
    'COUNT', 'SUM', 'AVG', 'MIN', 'MAX'
})

ALLOWED_DIRECTIONS = frozenset({'ASC', 'DESC'})


class ValidationError(Exception):
    """Custom exception for validation failures."""
    pass


class PreferenceService:
    """Business logic for managing user preferences with enhanced security."""
    
    def __init__(self, db_connection):
        self.pref_model = UserPreference(db_connection)
    
    def _validate_field_name(
        self, 
        field_name: str, 
        allowed_fields: frozenset,
        context: str = "field"
    ) -> None:
        """
        Validate field name against allowed list.
        
        SECURITY: Raises exception on validation failure (fail-secure).
        
        Args:
            field_name: Field name to validate
            allowed_fields: Allowlist of permitted field names
            context: Description for error messages
            
        Raises:
            ValidationError: If validation fails
        """
        if not field_name:
            raise ValidationError(f"Empty {context} name")
        
        # Check against allowlist (primary defense)
        if field_name not in allowed_fields:
            raise ValidationError(
                f"Invalid {context} name: '{field_name}' not in allowlist"
            )
        
        # Secondary defense: validate format (defense in depth)
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', field_name):
            raise ValidationError(
                f"Invalid {context} format: '{field_name}' contains illegal characters"
            )
    
    def _validate_direction(self, direction: str) -> None:
        """
        Validate sort direction.
        
        Args:
            direction: Sort direction (ASC/DESC)
            
        Raises:
            ValidationError: If direction invalid
        """
        direction_upper = direction.upper() if direction else ''
        if direction_upper not in ALLOWED_DIRECTIONS:
            raise ValidationError(
                f"Invalid direction: '{direction}'. Must be ASC or DESC"
            )
    
    def _validate_aggregate(self, aggregate: str) -> None:
        """
        Validate aggregate function name.
        
        Args:
            aggregate: Aggregate function name
            
        Raises:
            ValidationError: If aggregate invalid
        """
        aggregate_upper = aggregate.upper() if aggregate else ''
        if aggregate_upper not in ALLOWED_AGGREGATES:
            raise ValidationError(
                f"Invalid aggregate: '{aggregate}'. Must be one of {ALLOWED_AGGREGATES}"
            )
    
    def save_sort_preference(
        self, 
        user_id: int, 
        sort_field: str,
        direction: str = 'ASC'
    ) -> Dict[str, Any]:
        """
        Save user's sort preference with validation.
        
        SECURITY: Validates at write-time (first defense layer).
        """
        try:
            # Validate inputs
            self._validate_field_name(sort_field, ALLOWED_SORT_FIELDS, "sort field")
            self._validate_direction(direction)
            
            # Normalize direction
            direction_normalized = direction.upper()
            
            value = f"{sort_field}|{direction_normalized}"
            metadata = {
                'validated_at': 'input_time',
                'validation_passed': True,
                'field_type': 'sort',
                'validator_version': '2.0_secure'
            }
            
            self.pref_model.save_preference(
                user_id, 
                'default_sort', 
                value, 
                metadata
            )
            
            return {
                'success': True, 
                'field': sort_field, 
                'direction': direction_normalized
            }
        
        except ValidationError as e:
            return {'success': False, 'error': str(e)}
    
    def save_filter_preference(
        self,
        user_id: int,
        filter_field: str,
        filter_value: str
    ) -> Dict[str, Any]:
        """
        Save user's filter preference.
        
        SECURITY: Validates field name; value will be parameterized in queries.
        """
        try:
            self._validate_field_name(filter_field, ALLOWED_FILTER_FIELDS, "filter field")
            
            if not filter_value:
                raise ValidationError('Filter value required')
            
            # Note: filter_value stored as-is, will be used as parameter in queries
            value = f"{filter_field}|{filter_value}"
            metadata = {
                'validated_at': 'input_time',
                'validation_passed': True,
                'field_type': 'filter',
                'validator_version': '2.0_secure'
            }
            
            self.pref_model.save_preference(
                user_id,
                'default_filter',
                value,
                metadata
            )
            
            return {
                'success': True, 
                'field': filter_field, 
                'value': filter_value
            }
        
        except ValidationError as e:
            return {'success': False, 'error': str(e)}
    
    def save_groupby_preference(
        self,
        user_id: int,
        group_field: str,
        aggregate: str = 'COUNT'
    ) -> Dict[str, Any]:
        """
        Save user's group by preference.
        
        SECURITY: Validates both field and aggregate function.
        """
        try:
            self._validate_field_name(group_field, ALLOWED_GROUP_FIELDS, "group field")
            self._validate_aggregate(aggregate)
            
            # Normalize aggregate
            aggregate_normalized = aggregate.upper()
            
            value = f"{group_field}|{aggregate_normalized}"
            metadata = {
                'validated_at': 'input_time',
                'validation_passed': True,
                'field_type': 'groupby',
                'validator_version': '2.0_secure'
            }
            
            self.pref_model.save_preference(
                user_id,
                'default_groupby',
                value,
                metadata
            )
            
            return {
                'success': True, 
                'field': group_field, 
                'aggregate': aggregate_normalized
            }
        
        except ValidationError as e:
            return {'success': False, 'error': str(e)}
    
    def get_sort_preference(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve and VALIDATE user's sort preference.
        
        SECURITY CRITICAL: Re-validates data from database (execution-time validation).
        This protects against database compromise or corruption.
        """
        pref = self.pref_model.get_preference(user_id, 'default_sort')
        if not pref:
            return None
        
        # Parse stored value
        parts = pref['value'].split('|')
        if len(parts) != 2:
            # Malformed data - fail securely
            return None
        
        sort_field, direction = parts[0], parts[1]
        
        try:
            # EXECUTION-TIME VALIDATION (critical security layer)
            self._validate_field_name(sort_field, ALLOWED_SORT_FIELDS, "sort field")
            self._validate_direction(direction)
            
            return {
                'sort_field': sort_field,
                'direction': direction
            }
        
        except ValidationError:
            # Database contains invalid data - fail securely
            # Log this incident as it may indicate compromise
            return None
    
    def get_filter_preference(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve and VALIDATE user's filter preference.
        
        SECURITY CRITICAL: Re-validates field name from database.
        """
        pref = self.pref_model.get_preference(user_id, 'default_filter')
        if not pref:
            return None
        
        parts = pref['value'].split('|', 1)
        if len(parts) != 2:
            return None
        
        filter_field, filter_value = parts[0], parts[1]
        
        try:
            # EXECUTION-TIME VALIDATION
            self._validate_field_name(filter_field, ALLOWED_FILTER_FIELDS, "filter field")
            
            return {
                'filter_field': filter_field,
                'filter_value': filter_value  # Will be used as query parameter
            }
        
        except ValidationError:
            # Database contains invalid data - fail securely
            return None
    
    def get_groupby_preference(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve and VALIDATE user's group by preference.
        
        SECURITY CRITICAL: Re-validates both field and aggregate from database.
        """
        pref = self.pref_model.get_preference(user_id, 'default_groupby')
        if not pref:
            return None
        
        parts = pref['value'].split('|', 1)
        if len(parts) != 2:
            return None
        
        group_field, aggregate = parts[0], parts[1]
        
        try:
            # EXECUTION-TIME VALIDATION
            self._validate_field_name(group_field, ALLOWED_GROUP_FIELDS, "group field")
            self._validate_aggregate(aggregate)
            
            return {
                'group_field': group_field,
                'aggregate': aggregate
            }
        
        except ValidationError:
            # Database contains invalid data - fail securely
            return None
