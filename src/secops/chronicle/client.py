# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Chronicle API client."""
import re
import json
import ipaddress
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List, Tuple

from google.auth.transport import requests as google_auth_requests
from secops.auth import SecOpsAuth
from secops.exceptions import APIError

# Import functions from the new modules
from secops.chronicle.udm_search import fetch_udm_search_csv as _fetch_udm_search_csv
from secops.chronicle.validate import validate_query as _validate_query
from secops.chronicle.stats import get_stats as _get_stats
from secops.chronicle.search import search_udm as _search_udm
from secops.chronicle.entity import (
    summarize_entity as _summarize_entity,
    summarize_entities_from_query as _summarize_entities_from_query
)
from secops.chronicle.ioc import list_iocs as _list_iocs
from secops.chronicle.case import get_cases as _get_cases
from secops.chronicle.alert import get_alerts as _get_alerts

from secops.chronicle.models import (
    Entity, 
    EntityMetadata, 
    EntityMetrics, 
    TimeInterval, 
    TimelineBucket, 
    Timeline, 
    WidgetMetadata, 
    EntitySummary,
    AlertCount,
    CaseList
)

class ValueType(Enum):
    """Chronicle API value types."""
    ASSET_IP_ADDRESS = "ASSET_IP_ADDRESS"
    MAC = "MAC"
    HOSTNAME = "HOSTNAME"
    DOMAIN_NAME = "DOMAIN_NAME"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA256 = "HASH_SHA256"
    HASH_SHA1 = "HASH_SHA1"
    EMAIL = "EMAIL"
    USERNAME = "USERNAME"

def _detect_value_type(value: str) -> tuple[Optional[str], Optional[str]]:
    """Detect value type from a string.
    
    Args:
        value: The value to detect type for
        
    Returns:
        Tuple of (field_path, value_type) where one or both may be None
    """
    # Try to detect IP address
    try:
        ipaddress.ip_address(value)
        return "principal.ip", None
    except ValueError:
        pass
    
    # Try to detect MD5 hash
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "target.file.md5", None
    
    # Try to detect SHA-1 hash
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "target.file.sha1", None
    
    # Try to detect SHA-256 hash
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "target.file.sha256", None
    
    # Try to detect domain name
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$", value):
        return None, "DOMAIN_NAME"
    
    # Try to detect email address
    if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        return None, "EMAIL"
    
    # Try to detect MAC address
    if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", value):
        return None, "MAC"
    
    # Try to detect hostname (simple rule)
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", value):
        return None, "HOSTNAME"
    
    # If no match found
    return None, None

class ChronicleClient:
    """Client for the Chronicle API."""

    def __init__(
        self,
        project_id: str,
        customer_id: str,
        region: str = "us",
        auth: Optional[Any] = None,
        session: Optional[Any] = None,
        extra_scopes: Optional[List[str]] = None,
        credentials: Optional[Any] = None,
    ):
        """Initialize ChronicleClient.
        
        Args:
            project_id: Google Cloud project ID
            customer_id: Chronicle customer ID
            region: Chronicle region, typically "us" or "eu"
            auth: Authentication object
            session: Custom session object
            extra_scopes: Additional OAuth scopes
            credentials: Credentials object
        """
        self.project_id = project_id
        self.customer_id = customer_id
        self.region = region
        
        # Format the instance ID to match the expected format
        self.instance_id = f"projects/{project_id}/locations/{region}/instances/{customer_id}"
        
        # Set up the base URL
        self.base_url = f"https://{self.region}-chronicle.googleapis.com/v1alpha"
        
        # Create a session with authentication
        if session:
            self._session = session
        else:
            from secops import auth as secops_auth
            
            if auth is None:
                auth = secops_auth.SecOpsAuth(
                    scopes=[
                        "https://www.googleapis.com/auth/cloud-platform",
                        "https://www.googleapis.com/auth/chronicle-backstory",
                    ] + (extra_scopes or []),
                    credentials=credentials,
                )
                
            self._session = auth.session

    @property
    def session(self) -> google_auth_requests.AuthorizedSession:
        """Get an authenticated session.
        
        Returns:
            Authorized session for API requests
        """
        return self._session

    def fetch_udm_search_csv(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        fields: list[str],
        case_insensitive: bool = True
    ) -> str:
        """Fetch UDM search results in CSV format.
        
        Args:
            query: Chronicle search query
            start_time: Search start time
            end_time: Search end time
            fields: List of fields to include in results
            case_insensitive: Whether to perform case-insensitive search
            
        Returns:
            CSV formatted string of results
            
        Raises:
            APIError: If the API request fails
        """
        return _fetch_udm_search_csv(
            self,
            query,
            start_time,
            end_time,
            fields,
            case_insensitive
        )

    def validate_query(self, query: str) -> Dict[str, Any]:
        """Validate a Chronicle search query.
        
        Args:
            query: Chronicle search query to validate
            
        Returns:
            Dictionary with validation results
            
        Raises:
            APIError: If the API request fails
        """
        return _validate_query(self, query)

    def get_stats(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        max_values: int = 60,
        max_events: int = 10000,
        case_insensitive: bool = True,
        max_attempts: int = 30
    ) -> Dict[str, Any]:
        """Get statistics from a Chronicle search query.
        
        Args:
            query: Chronicle search query
            start_time: Search start time
            end_time: Search end time
            max_values: Maximum number of values to return per field
            max_events: Maximum number of events to process
            case_insensitive: Whether to perform case-insensitive search
            max_attempts: Maximum number of attempts to poll for results
            
        Returns:
            Dictionary with search statistics
            
        Raises:
            APIError: If the API request fails or times out
        """
        return _get_stats(
            self,
            query,
            start_time,
            end_time,
            max_values,
            max_events,
            case_insensitive,
            max_attempts
        )

    def _process_stats_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Process stats search results.
        
        Args:
            results: Stats search results from API
            
        Returns:
            Processed statistics
        """
        processed_results = {
            "total_rows": 0,
            "columns": [],
            "rows": []
        }
        
        # Return early if no stats results
        if "stats" not in results or "results" not in results["stats"]:
            return processed_results
        
        # Extract columns
        columns = []
        column_data = {}
        
        for col_data in results["stats"]["results"]:
            col_name = col_data.get("column", "")
            columns.append(col_name)
            
            # Process values for this column
            values = []
            for val_data in col_data.get("values", []):
                if "value" in val_data:
                    val = val_data["value"]
                    if "int64Val" in val:
                        values.append(int(val["int64Val"]))
                    elif "doubleVal" in val:
                        values.append(float(val["doubleVal"]))
                    elif "stringVal" in val:
                        values.append(val["stringVal"])
                    else:
                        values.append(None)
                else:
                    values.append(None)
            
            column_data[col_name] = values
        
        # Build result rows
        rows = []
        if columns and all(col in column_data for col in columns):
            max_rows = max(len(column_data[col]) for col in columns)
            processed_results["total_rows"] = max_rows
            
            for i in range(max_rows):
                row = {}
                for col in columns:
                    col_values = column_data[col]
                    row[col] = col_values[i] if i < len(col_values) else None
                rows.append(row)
        
        processed_results["columns"] = columns
        processed_results["rows"] = rows
        
        return processed_results

    def search_udm(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        max_events: int = 10000,
        case_insensitive: bool = True,
        max_attempts: int = 30
    ) -> Dict[str, Any]:
        """Search UDM events in Chronicle.
        
        Args:
            query: Chronicle search query
            start_time: Search start time
            end_time: Search end time
            max_events: Maximum number of events to return
            case_insensitive: Whether to perform case-insensitive search
            max_attempts: Maximum number of attempts to poll for results
            
        Returns:
            Dictionary with search results
            
        Raises:
            APIError: If the API request fails or times out
        """
        return _search_udm(
            self,
            query,
            start_time,
            end_time,
            max_events,
            case_insensitive,
            max_attempts
        )

    def summarize_entity(
        self,
        start_time: datetime,
        end_time: datetime,
        value: str,
        field_path: Optional[str] = None,
        value_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        entity_namespace: Optional[str] = None,
        return_alerts: bool = True,
        return_prevalence: bool = False,
        include_all_udm_types: bool = True,
        page_size: int = 1000,
        page_token: Optional[str] = None
    ) -> EntitySummary:
        """Get entity summary from Chronicle.
        
        Args:
            start_time: Start time for the summary
            end_time: End time for the summary
            value: Entity value to summarize
            field_path: Field path for the entity
            value_type: Entity value type
            entity_id: Entity ID
            entity_namespace: Entity namespace
            return_alerts: Whether to return alerts
            return_prevalence: Whether to return prevalence
            include_all_udm_types: Whether to include all UDM types
            page_size: Page size for results
            page_token: Page token for pagination
            
        Returns:
            Entity summary
            
        Raises:
            APIError: If the API request fails
            ValueError: If entity type cannot be determined
        """
        return _summarize_entity(
            self,
            start_time,
            end_time, 
            value,
            field_path,
            value_type,
            entity_id,
            entity_namespace,
            return_alerts,
            return_prevalence,
            include_all_udm_types,
            page_size,
            page_token
        )

    def summarize_entities_from_query(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
    ) -> List[EntitySummary]:
        """Get entity summaries from a query.
        
        Args:
            query: Chronicle search query
            start_time: Start time for the search
            end_time: End time for the search
            
        Returns:
            List of entity summaries
            
        Raises:
            APIError: If the API request fails
        """
        return _summarize_entities_from_query(
            self,
            query,
            start_time,
            end_time
        )

    def list_iocs(
        self,
        start_time: datetime,
        end_time: datetime,
        max_matches: int = 1000,
        add_mandiant_attributes: bool = True,
        prioritized_only: bool = False,
    ) -> dict:
        """List IoCs from Chronicle.
        
        Args:
            start_time: Start time for IoC search
            end_time: End time for IoC search
            max_matches: Maximum number of matches to return
            add_mandiant_attributes: Whether to add Mandiant attributes
            prioritized_only: Whether to only include prioritized IoCs
            
        Returns:
            Dictionary with IoC matches
            
        Raises:
            APIError: If the API request fails
        """
        return _list_iocs(
            self,
            start_time,
            end_time,
            max_matches,
            add_mandiant_attributes,
            prioritized_only
        )

    def get_cases(self, case_ids: list[str]) -> CaseList:
        """Get cases from Chronicle.
        
        Args:
            case_ids: List of case IDs to retrieve
            
        Returns:
            CaseList object with case details
            
        Raises:
            APIError: If the API request fails
            ValueError: If too many case IDs are provided
        """
        from secops.chronicle.case import get_cases_from_list
        return get_cases_from_list(self, case_ids)

    def get_alerts(
        self,
        start_time: datetime,
        end_time: datetime,
        snapshot_query: str = "feedback_summary.status != \"CLOSED\"",
        baseline_query: str = None,
        max_alerts: int = 1000,
        enable_cache: bool = True,
        max_attempts: int = 30,
        poll_interval: float = 1.0
    ) -> dict:
        """Get alerts from Chronicle.
        
        Args:
            start_time: Start time for alert search
            end_time: End time for alert search
            snapshot_query: Query to filter alerts
            baseline_query: Baseline query to compare against
            max_alerts: Maximum number of alerts to return
            enable_cache: Whether to use cached results
            max_attempts: Maximum number of attempts to poll for results
            poll_interval: Interval between polling attempts in seconds
            
        Returns:
            Dictionary with alert data
            
        Raises:
            APIError: If the API request fails or times out
        """
        return _get_alerts(
            self,
            start_time,
            end_time,
            snapshot_query,
            baseline_query,
            max_alerts,
            enable_cache,
            max_attempts,
            poll_interval
        )

    def _process_alerts_response(self, response) -> list:
        """Process alerts response.
        
        Args:
            response: Response data from API
            
        Returns:
            Processed response
        """
        # Simply return the response as it should already be processed
        return response

    def _merge_alert_updates(self, target: dict, updates: list) -> None:
        """Merge alert updates into the target dictionary.
        
        Args:
            target: Target dictionary to update
            updates: List of updates to apply
        """
        if "alerts" not in target or "alerts" not in target["alerts"]:
            return
        
        alerts = target["alerts"]["alerts"]
        
        # Create a map of alerts by ID for faster lookups
        alert_map = {alert["id"]: alert for alert in alerts}
        
        # Apply updates
        for update in updates:
            if "id" in update and update["id"] in alert_map:
                target_alert = alert_map[update["id"]]
                
                # Update each field
                for field, value in update.items():
                    if field != "id":
                        if isinstance(value, dict) and field in target_alert and isinstance(target_alert[field], dict):
                            # Merge nested dictionaries
                            target_alert[field].update(value)
                        else:
                            # Replace value
                            target_alert[field] = value

    def _fix_json_formatting(self, json_str: str) -> str:
        """Fix common JSON formatting issues.
        
        Args:
            json_str: JSON string to fix
            
        Returns:
            Fixed JSON string
        """
        # Fix trailing commas in objects
        json_str = re.sub(r',\s*}', '}', json_str)
        # Fix trailing commas in arrays
        json_str = re.sub(r',\s*]', ']', json_str)
        
        return json_str

    def _detect_value_type(self, value: str) -> tuple[Optional[str], Optional[str]]:
        """Instance method version of _detect_value_type for backward compatibility.
        
        Args:
            value: The value to detect type for
            
        Returns:
            Tuple of (field_path, value_type) where one or both may be None
        """
        return _detect_value_type(value)

    def _detect_value_type(self, value, value_type=None):
        """Detect value type for entity values.
        
        This is a legacy method maintained for backward compatibility.
        It calls the standalone detect_value_type function.
        
        Args:
            value: Value to detect type for
            value_type: Optional explicit value type
            
        Returns:
            Tuple of (field_path, value_type)
        """
        from secops.chronicle.entity import _detect_value_type
        return _detect_value_type(value, value_type) 