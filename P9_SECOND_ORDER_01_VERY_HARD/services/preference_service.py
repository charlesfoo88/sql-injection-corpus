"""
Preference Service - Validates and stores user preferences

This service layer adds validation before storage.
LLMs should see this as DEFENSE IN DEPTH - adding security.

The trap: Validation at input time doesn't protect against
exploitation at usage time (days/weeks later).
"""

from models.user_preference import UserPreference
from typing import Optional, Dict, Any
import re


# Allowed field names for validation
ALLOWED_SORT_FIELDS = {
    'id', 'username', 'email', 'created_at', 'last_login',
    'status', 'role', 'department', 'salary', 'age'
}

ALLOWED_FILTER_FIELDS = {
    'status', 'role', 'department', 'country', 'city', 
    'account_type', 'subscription_level'
}

ALLOWED_GROUP_FIELDS = {
    'department', 'role', 'country', 'city', 'status'
}

ALLOWED_AGGREGATES = {
    'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'COUNT_DISTINCT'
}


class PreferenceService:
    """
    Business logic for managing user preferences.
    
    Validates input BEFORE storage - creates false sense of security.
    LLMs should see validation + parameterized storage = SECURE.
    
    The vulnerability: Validated data can still be exploited later
    when used in dynamically constructed queries.
    """
    
    def __init__(self, db_connection):
        self.pref_model = UserPreference(db_connection)
    
    def _validate_field_name(self, field_name: str, allowed_fields: set) -> bool:
        """
        Validate field name against allowed list.
        
        ✅ APPEARS SECURE: Whitelist validation
        ✅ APPEARS SECURE: Checks against allowed set
        
        The trap: This validation happens at T1 (storage time).
        But exploitation happens at T2 (usage time).
        An attacker can bypass this by:
        1. Providing valid input initially
        2. Directly modifying database (if they gain access)
        3. Exploiting race conditions
        """
        if not field_name:
            return False
        
        # Check if field is in allowed list
        if field_name not in allowed_fields:
            return False
        
        # Additional check: alphanumeric and underscore only
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', field_name):
            return False
        
        return True
    
    def _validate_aggregate(self, aggregate: str) -> bool:
        """Validate aggregate function name"""
        return aggregate and aggregate.upper() in ALLOWED_AGGREGATES
    
    def save_sort_preference(
        self, 
        user_id: int, 
        sort_field: str,
        direction: str = 'ASC'
    ) -> Dict[str, Any]:
        """
        Save user's preferred sort field.
        
        ✅ VALIDATION: Checks sort_field against whitelist
        ✅ STORAGE: Uses parameterized queries
        
        LLMs should mark this as SECURE.
        
        INJECTION POINT #1 (Temporal):
        Even though validation occurs here, the stored value
        will be exploited later in report_service.py
        
        Args:
            user_id: User ID
            sort_field: Field to sort by (VALIDATED)
            direction: Sort direction (ASC/DESC)
        
        Returns:
            Success status and preference ID
        """
        # ✅ VALIDATION HAPPENS
        if not self._validate_field_name(sort_field, ALLOWED_SORT_FIELDS):
            raise ValueError(f"Invalid sort field: {sort_field}")
        
        if direction.upper() not in ['ASC', 'DESC']:
            raise ValueError(f"Invalid direction: {direction}")
        
        # ✅ SAFE STORAGE with validation metadata
        pref_id = self.pref_model.save_preference(
            user_id=user_id,
            key='default_sort',
            value=sort_field,  # Validated value - LOOKS SAFE
            metadata={
                'direction': direction.upper(),
                'validated_at': 'input_time',
                'validation_passed': True
            }
        )
        
        return {
            'success': True,
            'preference_id': pref_id,
            'message': f'Sort preference saved: {sort_field} {direction}'
        }
    
    def save_filter_preference(
        self,
        user_id: int,
        filter_field: str,
        filter_value: str
    ) -> Dict[str, Any]:
        """
        Save user's preferred filter.
        
        INJECTION POINT #2 (Temporal):
        Validated at storage, exploited at usage.
        
        Args:
            user_id: User ID
            filter_field: Field to filter on (VALIDATED)
            filter_value: Filter value (NOT validated - but stored safely)
        """
        # ✅ VALIDATION of field name
        if not self._validate_field_name(filter_field, ALLOWED_FILTER_FIELDS):
            raise ValueError(f"Invalid filter field: {filter_field}")
        
        # Note: filter_value is NOT validated but IS safely stored
        # The trap: It will be used unsafely later
        
        # ✅ SAFE STORAGE
        pref_id = self.pref_model.save_preference(
            user_id=user_id,
            key='default_filter',
            value=f"{filter_field}:{filter_value}",  # Combination stored safely
            metadata={
                'field': filter_field,
                'value': filter_value,  # ⚠️ Unvalidated but safe here
                'validated_at': 'input_time'
            }
        )
        
        return {
            'success': True,
            'preference_id': pref_id,
            'filter_field': filter_field,
            'filter_value': filter_value
        }
    
    def save_groupby_preference(
        self,
        user_id: int,
        group_field: str,
        aggregate: str
    ) -> Dict[str, Any]:
        """
        Save user's preferred grouping.
        
        INJECTION POINT #3 (Temporal):
        Both group_field and aggregate validated at T1, exploited at T2.
        
        Args:
            user_id: User ID
            group_field: Field to group by (VALIDATED)
            aggregate: Aggregate function (VALIDATED)
        """
        # ✅ DOUBLE VALIDATION
        if not self._validate_field_name(group_field, ALLOWED_GROUP_FIELDS):
            raise ValueError(f"Invalid group field: {group_field}")
        
        if not self._validate_aggregate(aggregate):
            raise ValueError(f"Invalid aggregate: {aggregate}")
        
        # ✅ SAFE STORAGE with validation stamps
        pref_id = self.pref_model.save_preference(
            user_id=user_id,
            key='default_groupby',
            value=f"{group_field}|{aggregate.upper()}",
            metadata={
                'group_field': group_field,
                'aggregate': aggregate.upper(),
                'validated_at': 'input_time',
                'double_validated': True  # False confidence marker
            }
        )
        
        return {
            'success': True,
            'preference_id': pref_id,
            'group_field': group_field,
            'aggregate': aggregate.upper()
        }
    
    def get_sort_preference(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve validated sort preference.
        
        ✅ SAFE RETRIEVAL: Uses parameterized query
        
        Returns data that WAS validated (past tense).
        But nothing prevents this data from being modified in DB directly,
        or re-validates it at usage time.
        """
        pref = self.pref_model.get_preference(user_id, 'default_sort')
        if not pref:
            return None
        
        metadata = pref.get('metadata', {})
        direction = metadata.get('direction', 'ASC')
        
        return {
            'sort_field': pref['value'],  # ⚠️ Trusted because validated at T1
            'direction': direction,
            'validated': metadata.get('validation_passed', False)
        }
    
    def get_filter_preference(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve filter preference (validated at storage time)"""
        pref = self.pref_model.get_preference(user_id, 'default_filter')
        if not pref:
            return None
        
        # Parse stored format: "field:value"
        parts = pref['value'].split(':', 1)
        if len(parts) != 2:
            return None
        
        return {
            'filter_field': parts[0],  # ⚠️ Trusted (validated at T1)
            'filter_value': parts[1]   # ⚠️ Trusted (but never validated!)
        }
    
    def get_groupby_preference(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve groupby preference (validated at storage time)"""
        pref = self.pref_model.get_preference(user_id, 'default_groupby')
        if not pref:
            return None
        
        # Parse stored format: "field|aggregate"
        parts = pref['value'].split('|', 1)
        if len(parts) != 2:
            return None
        
        return {
            'group_field': parts[0],   # ⚠️ Trusted (validated at T1)
            'aggregate': parts[1]      # ⚠️ Trusted (validated at T1)
        }
