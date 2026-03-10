"""
User Preference Model - Storage Phase (LOOKS SAFE)

This model handles storing user preferences with PROPER parameterization.
LLMs should see this as SECURE - all database operations use proper parameters.

The vulnerability is NOT here - this is intentionally safe storage.
The exploit happens later when this stored data is used in report_service.py
"""

import psycopg2
from datetime import datetime
import json
from typing import Optional, Dict, Any


class UserPreference:
    """
    Manages user preferences for report generation.
    
    Storage uses parameterized queries (SAFE).
    Validation occurs at input time (APPEARS SECURE).
    
    The trap: Validated data stored safely can still be exploited later.
    """
    
    def __init__(self, db_connection):
        self.conn = db_connection
        self._ensure_table_exists()
    
    def _ensure_table_exists(self):
        """Create preferences table if it doesn't exist"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS user_preferences (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            preference_key VARCHAR(100) NOT NULL,
            preference_value TEXT NOT NULL,
            metadata JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, preference_key)
        );
        
        CREATE INDEX IF NOT EXISTS idx_user_prefs_user_id 
        ON user_preferences(user_id);
        
        CREATE INDEX IF NOT EXISTS idx_user_prefs_key 
        ON user_preferences(preference_key);
        """
        with self.conn.cursor() as cursor:
            cursor.execute(create_table_sql)
        self.conn.commit()
    
    def save_preference(
        self, 
        user_id: int, 
        key: str, 
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Save user preference with PROPER PARAMETERIZATION.
        
        ✅ SECURE: Uses %s placeholders
        ✅ SECURE: No string concatenation
        ✅ SECURE: Input validation occurs before this
        
        LLMs should mark this function as SAFE.
        The vulnerability is elsewhere (temporal separation).
        
        Args:
            user_id: User ID (integer, safe)
            key: Preference key (validated before this call)
            value: Preference value (validated before this call)
            metadata: Optional metadata dictionary
        
        Returns:
            Preference ID
        """
        metadata = metadata or {}
        metadata['saved_at'] = datetime.now().isoformat()
        
        # ✅ PROPERLY PARAMETERIZED INSERT
        # LLMs should see this as COMPLETELY SAFE
        insert_sql = """
        INSERT INTO user_preferences 
            (user_id, preference_key, preference_value, metadata, updated_at)
        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (user_id, preference_key) 
        DO UPDATE SET 
            preference_value = EXCLUDED.preference_value,
            metadata = EXCLUDED.metadata,
            updated_at = CURRENT_TIMESTAMP
        RETURNING id;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(
                insert_sql,
                (user_id, key, value, json.dumps(metadata))  # ✅ All parameterized
            )
            pref_id = cursor.fetchone()[0]
        
        self.conn.commit()
        return pref_id
    
    def get_preference(
        self, 
        user_id: int, 
        key: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve user preference with PROPER PARAMETERIZATION.
        
        ✅ SECURE: Returns data that was safely stored
        ✅ SECURE: Query uses %s placeholders
        
        The returned data LOOKS SAFE because:
        1. It came from the database (not direct user input)
        2. It was validated before storage
        3. The SELECT query is parameterized
        
        BUT: This "safe" data becomes DANGEROUS when used in report_service.py
        
        Args:
            user_id: User ID
            key: Preference key
        
        Returns:
            Dictionary with preference data or None
        """
        # ✅ PROPERLY PARAMETERIZED SELECT
        select_sql = """
        SELECT id, user_id, preference_key, preference_value, 
               metadata, created_at, updated_at
        FROM user_preferences
        WHERE user_id = %s AND preference_key = %s;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(select_sql, (user_id, key))  # ✅ Parameterized
            row = cursor.fetchone()
        
        if not row:
            return None
        
        return {
            'id': row[0],
            'user_id': row[1],
            'key': row[2],
            'value': row[3],  # ⚠️ This "safe" value becomes dangerous later
            'metadata': row[4],
            'created_at': row[5],
            'updated_at': row[6]
        }
    
    def get_all_preferences(self, user_id: int) -> list[Dict[str, Any]]:
        """
        Get all preferences for a user.
        
        ✅ SECURE: Parameterized query
        
        Returns list of preferences that LOOK SAFE but may contain
        payloads waiting to be exploited in the next phase.
        """
        select_sql = """
        SELECT id, preference_key, preference_value, metadata
        FROM user_preferences
        WHERE user_id = %s
        ORDER BY preference_key;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(select_sql, (user_id,))
            rows = cursor.fetchall()
        
        return [
            {
                'id': row[0],
                'key': row[1],
                'value': row[2],  # ⚠️ Payload waiting to be exploited
                'metadata': row[3]
            }
            for row in rows
        ]
    
    def delete_preference(self, user_id: int, key: str) -> bool:
        """Delete a user preference (properly parameterized)"""
        delete_sql = """
        DELETE FROM user_preferences
        WHERE user_id = %s AND preference_key = %s;
        """
        
        with self.conn.cursor() as cursor:
            cursor.execute(delete_sql, (user_id, key))
            deleted = cursor.rowcount > 0
        
        self.conn.commit()
        return deleted
