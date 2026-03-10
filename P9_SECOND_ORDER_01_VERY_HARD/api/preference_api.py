"""
Preference API - REST endpoints for saving preferences

This API layer adds another degree of separation:
HTTP Request → Validate → Service Layer → Model → Database

Makes it harder for LLMs to trace the full data flow.
"""

from services.preference_service import PreferenceService
from validators import (
    validate_sql_identifier,
    validate_sort_direction,
    validate_filter_value,
    check_dangerous_patterns,
    sanitize_string_for_logging
)
from typing import Dict, Any
import json


class PreferenceAPI:
    """
    REST API endpoints for user preference management.
    
    This layer adds validation + service calls.
    Each layer looking secure makes the overall vulnerability harder to spot.
    """
    
    def __init__(self, db_connection):
        self.pref_service = PreferenceService(db_connection)
    
    def set_sort_preference(
        self,
        user_id: int,
        sort_field: str,
        direction: str = 'ASC'
    ) -> Dict[str, Any]:
        """
        API endpoint: Set user's default sort preference.
        
        ✅ Validates sort_field format
        ✅ Validates direction
        ✅ Checks dangerous patterns
        ✅ Logs safely
        ✅ Calls service layer (which validates again)
        
        INJECTION POINT #1 (Temporal - API Layer):
        Even with double validation (API + Service), stored value
        will be exploited at T2 in report_service.py
        
        Args:
            user_id: User ID from authentication
            sort_field: Field name to sort by
            direction: ASC or DESC
        
        Returns:
            API response dict
        """
        try:
            # ✅ VALIDATION LAYER 1: API level
            is_valid, error = validate_sql_identifier(sort_field)
            if not is_valid:
                return {
                    'status': 'error',
                    'code': 400,
                    'message': f'Invalid sort field: {error}'
                }
            
            is_valid, error = validate_sort_direction(direction)
            if not is_valid:
                return {
                    'status': 'error',
                    'code': 400,
                    'message': f'Invalid direction: {error}'
                }
            
            # ✅ Check for dangerous patterns
            is_safe, error = check_dangerous_patterns(sort_field)
            if not is_safe:
                return {
                    'status': 'error',
                    'code': 400,
                    'message': f'Security check failed: {error}'
                }
            
            # ✅ Safe logging
            safe_field = sanitize_string_for_logging(sort_field)
            print(f"[API] User {user_id} setting sort preference: {safe_field}")
            
            # ✅ VALIDATION LAYER 2: Service level (will validate again)
            result = self.pref_service.save_sort_preference(
                user_id=user_id,
                sort_field=sort_field,  # Validated twice, looks very safe
                direction=direction
            )
            
            return {
                'status': 'success',
                'code': 200,
                'data': result,
                'message': 'Sort preference saved successfully'
            }
            
        except ValueError as e:
            return {
                'status': 'error',
                'code': 400,
                'message': str(e)
            }
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': 'Internal server error'
            }
    
    def set_filter_preference(
        self,
        user_id: int,
        filter_field: str,
        filter_value: str
    ) -> Dict[str, Any]:
        """
        API endpoint: Set user's default filter.
        
        INJECTION POINT #2 (Temporal - API Layer):
        Field name validated, value weakly validated.
        Both stored safely, exploited unsafely later.
        
        Args:
            user_id: User ID
            filter_field: Field to filter on (validated)
            filter_value: Value to filter by (weakly validated)
        """
        try:
            # ✅ Validate field name
            is_valid, error = validate_sql_identifier(filter_field)
            if not is_valid:
                return {
                    'status': 'error',
                    'code': 400,
                    'message': f'Invalid filter field: {error}'
                }
            
            # ⚠️ WEAK validation of filter value
            # Only checks not empty, doesn't check for SQL syntax
            is_valid, error = validate_filter_value(filter_value)
            if not is_valid:
                return {
                    'status': 'error',
                    'code': 400,
                    'message': f'Invalid filter value: {error}'
                }
            
            # ⚠️ Dangerous pattern check (bypassable blacklist)
            is_safe, error = check_dangerous_patterns(filter_value)
            if not is_safe:
                return {
                    'status': 'error',
                    'code': 400,
                    'message': f'Security check failed: {error}'
                }
            
            # Safe logging
            safe_field = sanitize_string_for_logging(filter_field)
            safe_value = sanitize_string_for_logging(filter_value, max_length=50)
            print(f"[API] User {user_id} setting filter: {safe_field}={safe_value}")
            
            # Service layer call
            result = self.pref_service.save_filter_preference(
                user_id=user_id,
                filter_field=filter_field,
                filter_value=filter_value  # Weakly validated, safely stored, unsafely used
            )
            
            return {
                'status': 'success',
                'code': 200,
                'data': result,
                'message': 'Filter preference saved successfully'
            }
            
        except ValueError as e:
            return {
                'status': 'error',
                'code': 400,
                'message': str(e)
            }
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': 'Internal server error'
            }
    
    def set_groupby_preference(
        self,
        user_id: int,
        group_field: str,
        aggregate: str
    ) -> Dict[str, Any]:
        """
        API endpoint: Set user's grouping preference.
        
        INJECTION POINT #3 (Temporal - API Layer):
        Both parameters validated at API and Service layers.
        Still vulnerable at usage time.
        """
        try:
            # Validate group field
            is_valid, error = validate_sql_identifier(group_field)
            if not is_valid:
                return {
                    'status': 'error',
                    'code': 400,
                    'message': f'Invalid group field: {error}'
                }
            
            # Validate aggregate function - APPEARS VERY SECURE
            from validators import validate_aggregate_function
            is_valid, error = validate_aggregate_function(aggregate)
            if not is_valid:
                return {
                    'status': 'error',
                    'code': 400,
                    'message': f'Invalid aggregate: {error}'
                }
            
            # Service layer call (will validate AGAIN)
            result = self.pref_service.save_groupby_preference(
                user_id=user_id,
                group_field=group_field,  # Triple validated!
                aggregate=aggregate        # Triple validated!
            )
            
            return {
                'status': 'success',
                'code': 200,
                'data': result,
                'message': 'GroupBy preference saved successfully'
            }
            
        except ValueError as e:
            return {
                'status': 'error',
                'code': 400,
                'message': str(e)
            }
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': 'Internal server error'
            }
    
    def get_all_preferences(self, user_id: int) -> Dict[str, Any]:
        """
        Get all preferences for a user.
        
        Returns validated, safely-stored data that looks completely safe.
        """
        try:
            prefs = {}
            
            sort_pref = self.pref_service.get_sort_preference(user_id)
            if sort_pref:
                prefs['sort'] = sort_pref
            
            filter_pref = self.pref_service.get_filter_preference(user_id)
            if filter_pref:
                prefs['filter'] = filter_pref
            
            group_pref = self.pref_service.get_groupby_preference(user_id)
            if group_pref:
                prefs['groupby'] = group_pref
            
            return {
                'status': 'success',
                'code': 200,
                'data': prefs
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': 'Internal server error'
            }
