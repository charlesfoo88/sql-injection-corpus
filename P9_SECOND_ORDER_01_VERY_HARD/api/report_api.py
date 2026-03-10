"""
Report API - REST endpoints for report generation

This is where users trigger the report generation that exploits
the second-order SQL injection vulnerabilities.
"""

from services.report_service import ReportService
from models.report_config import ReportConfig
from typing import Dict, Any, List


class ReportAPI:
    """
    REST API endpoints for report generation.
    
    These endpoints trigger the vulnerable report_service.py functions
    that use stored "validated" data unsafely.
    """
    
    def __init__(self, db_connection):
        self.report_service = ReportService(db_connection)
        self.config_model = ReportConfig(db_connection)
    
    def get_user_report(
        self,
        user_id: int,
        use_preferences: bool = True
    ) -> Dict[str, Any]:
        """
        API endpoint: Generate report using user preferences.
        
        🔴 Triggers INJECTION POINT #1 in report_service.py
        
        This looks like a normal API endpoint:
        - Takes user ID (from auth)
        - Optional flag to use preferences
        - Returns report data
        
        BUT: Internally calls generate_user_report() which uses
        stored sort preference in f-string.
        
        Args:
            user_id: Authenticated user ID
            use_preferences: Apply saved preferences
        
        Returns:
            API response with report data
        """
        try:
            data = self.report_service.generate_user_report(
                user_id=user_id,
                use_preferences=use_preferences
            )
            
            return {
                'status': 'success',
                'code': 200,
                'report_type': 'user_report',
                'row_count': len(data),
                'data': data
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': str(e)
            }
    
    def get_filtered_report(self, user_id: int) -> Dict[str, Any]:
        """
        API endpoint: Generate filtered report.
        
        🔴 Triggers INJECTION POINT #2 in report_service.py
        
        Uses filter preferences saved earlier.
        Looks innocent but exploits second-order injection.
        
        Args:
            user_id: Authenticated user ID
        
        Returns:
            Filtered report data
        """
        try:
            data = self.report_service.generate_filtered_report(user_id)
            
            return {
                'status': 'success',
                'code': 200,
                'report_type': 'filtered_report',
                'row_count': len(data),
                'data': data
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': str(e)
            }
    
    def get_grouped_report(self, user_id: int) -> Dict[str, Any]:
        """
        API endpoint: Generate grouped aggregated report.
        
        🔴 Triggers INJECTION POINT #3 in report_service.py
        
        Uses groupby preferences for GROUP BY and aggregation.
        
        Args:
            user_id: Authenticated user ID
        
        Returns:
            Grouped report data
        """
        try:
            data = self.report_service.generate_grouped_report(user_id)
            
            return {
                'status': 'success',
                'code': 200,
                'report_type': 'grouped_report',
                'row_count': len(data),
                'data': data
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': str(e)
            }
    
    def create_report_config(
        self,
        user_id: int,
        report_name: str,
        sort_field: str = None,
        filter_field: str = None,
        group_by_field: str = None,
        aggregate_function: str = None
    ) -> Dict[str, Any]:
        """
        API endpoint: Create new report configuration.
        
        Saves report config with fields from preferences.
        These configs are stored safely, exploited later.
        
        Args:
            user_id: User ID
            report_name: Name for the config
            sort_field: Field to sort by
            filter_field: Field to filter by
            group_by_field: Field to group by
            aggregate_function: Aggregate function
        
        Returns:
            Created config info
        """
        try:
            from validators import validate_report_name
            
            # Validate report name
            is_valid, error = validate_report_name(report_name)
            if not is_valid:
                return {
                    'status': 'error',
                    'code': 400,
                    'message': f'Invalid report name: {error}'
                }
            
            # Create config (parameterized storage - SAFE)
            config_id = self.config_model.create_config(
                user_id=user_id,
                report_name=report_name,
                sort_field=sort_field,
                filter_field=filter_field,
                group_by_field=group_by_field,
                aggregate_function=aggregate_function
            )
            
            return {
                'status': 'success',
                'code': 201,
                'message': 'Report configuration created',
                'config_id': config_id
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': str(e)
            }
    
    def generate_from_config(self, config_id: int) -> Dict[str, Any]:
        """
        API endpoint: Generate report from saved configuration.
        
        🔴 Triggers INJECTION POINT #4 in report_service.py
        
        Most complex temporal chain:
        Input → Preferences → Config → Report
        
        Args:
            config_id: Report configuration ID
        
        Returns:
            Generated report
        """
        try:
            result = self.report_service.generate_from_config(config_id)
            
            return {
                'status': 'success',
                'code': 200,
                'report': result
            }
            
        except ValueError as e:
            return {
                'status': 'error',
                'code': 404,
                'message': str(e)
            }
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': str(e)
            }
    
    def list_user_configs(self, user_id: int) -> Dict[str, Any]:
        """
        List all report configurations for a user.
        
        Safe endpoint - just retrieves config metadata.
        """
        try:
            configs = self.config_model.get_user_configs(user_id)
            
            return {
                'status': 'success',
                'code': 200,
                'count': len(configs),
                'configs': configs
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'code': 500,
                'message': str(e)
            }
