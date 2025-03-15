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
"""Entity functionality for Chronicle."""
from datetime import datetime
from typing import Dict, Any, List, Optional
from secops.exceptions import APIError
from secops.chronicle.models import (
    Entity,
    EntityMetadata,
    EntityMetrics,
    TimeInterval,
    TimelineBucket,
    Timeline,
    WidgetMetadata,
    EntitySummary,
    AlertCount
)

def summarize_entity(
    client,
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
    """Get summary information about an entity.
    
    Args:
        client: ChronicleClient instance
        start_time: Start time for the summary
        end_time: End time for the summary
        value: Value to search for (IP, domain, file hash, etc)
        field_path: Optional override for UDM field path
        value_type: Optional override for value type
        entity_id: Entity ID to look up
        entity_namespace: Entity namespace
        return_alerts: Whether to include alerts
        return_prevalence: Whether to include prevalence data
        include_all_udm_types: Whether to include all UDM event types
        page_size: Maximum number of results per page
        page_token: Token for pagination
        
    Returns:
        EntitySummary object containing the results
        
    Raises:
        APIError: If the API request fails
    """
    url = f"{client.base_url}/{client.instance_id}:summarizeEntity"
    
    params = {
        "timeRange.startTime": start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "timeRange.endTime": end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "returnAlerts": return_alerts,
        "returnPrevalence": return_prevalence,
        "includeAllUdmEventTypesForFirstLastSeen": include_all_udm_types,
        "pageSize": page_size
    }

    # Add optional parameters
    if page_token:
        params["pageToken"] = page_token
    
    if entity_id:
        params["entityId"] = entity_id
    else:
        # Auto-detect type if not explicitly provided
        detected_field_path, detected_value_type = _detect_value_type(value)
        
        # Use explicit values if provided, otherwise use detected values
        final_field_path = field_path or detected_field_path
        final_value_type = value_type or detected_value_type
        
        if final_field_path:
            params["fieldAndValue.fieldPath"] = final_field_path
            params["fieldAndValue.value"] = value
        elif final_value_type:
            params["fieldAndValue.value"] = value
            params["fieldAndValue.valueType"] = final_value_type
        else:
            raise ValueError(
                f"Could not determine type for value: {value}. "
                "Please specify field_path or value_type explicitly."
            )
            
        if entity_namespace:
            params["fieldAndValue.entityNamespace"] = entity_namespace

    response = client.session.get(url, params=params)
    
    if response.status_code != 200:
        raise APIError(f"Error getting entity summary: {response.text}")
    
    try:
        data = response.json()
        
        # Parse entities
        entities = []
        for entity_data in data.get("entities", []):
            metadata = entity_data.get("metadata", {})
            interval = metadata.get("interval", {})
            
            entity = Entity(
                name=entity_data.get("name", ""),
                metadata=EntityMetadata(
                    entity_type=metadata.get("entityType", ""),
                    interval=TimeInterval(
                        start_time=datetime.fromisoformat(interval.get("startTime").replace('Z', '+00:00')),
                        end_time=datetime.fromisoformat(interval.get("endTime").replace('Z', '+00:00'))
                    )
                ),
                metric=EntityMetrics(
                    first_seen=datetime.fromisoformat(entity_data.get("metric", {}).get("firstSeen").replace('Z', '+00:00')),
                    last_seen=datetime.fromisoformat(entity_data.get("metric", {}).get("lastSeen").replace('Z', '+00:00'))
                ),
                entity=entity_data.get("entity", {})
            )
            entities.append(entity)
            
        # Parse alert counts
        alert_counts = []
        for alert_data in data.get("alertCounts", []):
            alert_counts.append(AlertCount(
                rule=alert_data.get("rule", ""),
                count=int(alert_data.get("count", 0))
            ))
            
        # Parse timeline
        timeline_data = data.get("timeline", {})
        timeline = Timeline(
            buckets=[TimelineBucket(**bucket) for bucket in timeline_data.get("buckets", [])],
            bucket_size=timeline_data.get("bucketSize", "")
        ) if timeline_data else None
        
        # Parse widget metadata
        widget_data = data.get("widgetMetadata")
        widget_metadata = WidgetMetadata(
            uri=widget_data.get("uri", ""),
            detections=widget_data.get("detections", 0),
            total=widget_data.get("total", 0)
        ) if widget_data else None
        
        return EntitySummary(
            entities=entities,
            alert_counts=alert_counts,
            timeline=timeline,
            widget_metadata=widget_metadata,
            has_more_alerts=data.get("hasMoreAlerts", False),
            next_page_token=data.get("nextPageToken")
        )
        
    except Exception as e:
        raise APIError(f"Error parsing entity summary response: {str(e)}")

def summarize_entities_from_query(
    client,
    query: str,
    start_time: datetime,
    end_time: datetime,
) -> List[EntitySummary]:
    """Get entity summaries from a UDM query.
    
    Args:
        client: ChronicleClient instance
        query: UDM query to find entities
        start_time: Start time for the summary
        end_time: End time for the summary
        
    Returns:
        List of EntitySummary objects containing the results
        
    Raises:
        APIError: If the API request fails
    """
    url = f"{client.base_url}/{client.instance_id}:summarizeEntitiesFromQuery"
    
    params = {
        "query": query,
        "timeRange.startTime": start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "timeRange.endTime": end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }

    response = client.session.get(url, params=params)
    
    if response.status_code != 200:
        raise APIError(f"Error getting entity summaries: {response.text}")
    
    try:
        data = response.json()
        summaries = []
        
        for summary_data in data.get("entitySummaries", []):
            entities = []
            for entity_data in summary_data.get("entity", []):
                metadata = entity_data.get("metadata", {})
                interval = metadata.get("interval", {})
                
                entity = Entity(
                    name=entity_data.get("name", ""),
                    metadata=EntityMetadata(
                        entity_type=metadata.get("entityType", ""),
                        interval=TimeInterval(
                            start_time=datetime.fromisoformat(interval.get("startTime").replace('Z', '+00:00')),
                            end_time=datetime.fromisoformat(interval.get("endTime").replace('Z', '+00:00'))
                        )
                    ),
                    metric=EntityMetrics(
                        first_seen=datetime.fromisoformat(entity_data.get("metric", {}).get("firstSeen").replace('Z', '+00:00')),
                        last_seen=datetime.fromisoformat(entity_data.get("metric", {}).get("lastSeen").replace('Z', '+00:00'))
                    ),
                    entity=entity_data.get("entity", {})
                )
                entities.append(entity)
                
            summary = EntitySummary(entities=entities)
            summaries.append(summary)
            
        return summaries
        
    except Exception as e:
        raise APIError(f"Error parsing entity summaries response: {str(e)}")

def _detect_value_type(value, value_type=None):
    """Detect the value type for entity values.
    
    Args:
        value: The value to detect the type for
        value_type: Optional explicit value type
        
    Returns:
        Tuple of (field_path, value_type)
    """
    import re
    
    # Return the provided value_type if explicitly specified
    if value_type:
        # Map common value types to their respective field paths
        if value_type.lower() == "ip":
            return ("network.ip", "IP_ADDRESS")
        elif value_type.lower() == "domain":
            return ("network.domain_name", "DOMAIN_NAME")
        elif value_type.lower() == "hash":
            # Determine hash type based on length
            hash_length = len(value)
            if hash_length == 32:
                return ("file.md5", "HASH_MD5")
            elif hash_length == 40:
                return ("file.sha1", "HASH_SHA1")
            elif hash_length == 64:
                return ("file.sha256", "HASH_SHA256")
            else:
                return ("file.hash", "HASH")
        elif value_type.lower() == "email":
            return ("user.email_addresses", "EMAIL_ADDRESS")
        else:
            # Default field path for custom value types
            return (None, value_type)
    
    # Attempt to auto-detect value type based on pattern matching
    # IP address pattern
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
        return ("network.ip", "IP_ADDRESS")
    
    # Domain name pattern
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$', value):
        return ("network.domain_name", "DOMAIN_NAME")
    
    # Email address pattern
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
        return ("user.email_addresses", "EMAIL_ADDRESS")
    
    # MAC address pattern (with : or - separators)
    if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', value):
        return ("network.mac", "MAC_ADDRESS")
    
    # Hash pattern (simple check based on character set and length)
    if re.match(r'^[a-fA-F0-9]+$', value):
        hash_length = len(value)
        if hash_length == 32:
            return ("file.md5", "HASH_MD5")
        elif hash_length == 40:
            return ("file.sha1", "HASH_SHA1")
        elif hash_length == 64:
            return ("file.sha256", "HASH_SHA256")
    
    # Default if type cannot be determined
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', value):
        return ("principal.hostname", "HOSTNAME")
        
    return (None, None) 