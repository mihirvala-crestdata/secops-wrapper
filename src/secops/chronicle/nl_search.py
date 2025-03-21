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
"""Natural language search functionality for Chronicle."""

from datetime import datetime
from typing import Dict, Any, Optional
from secops.exceptions import APIError

def translate_nl_to_udm(
    client,
    text: str
) -> str:
    """Translate natural language query to UDM search syntax.
    
    Args:
        client: ChronicleClient instance
        text: Natural language query text
        
    Returns:
        UDM search query string
        
    Raises:
        APIError: If the API request fails or no valid query can be generated
    """
    url = f"https://{client.region}-chronicle.googleapis.com/v1alpha/projects/{client.project_id}/locations/{client.region}/instances/{client.customer_id}:translateUdmQuery"
    
    payload = {
        "text": text
    }
    
    response = client.session.post(url, json=payload)
    
    if response.status_code != 200:
        raise APIError(f"Chronicle API request failed: {response.text}")
    
    result = response.json()
    
    if "message" in result:
        raise APIError(result["message"])
    
    return result.get("query", "")

def nl_search(
    client,
    text: str,
    start_time: datetime,
    end_time: datetime,
    max_events: int = 10000,
    case_insensitive: bool = True,
    max_attempts: int = 30
) -> Dict[str, Any]:
    """Perform a search using natural language that is translated to UDM.
    
    Args:
        client: ChronicleClient instance
        text: Natural language query text
        start_time: Search start time
        end_time: Search end time
        max_events: Maximum events to return
        case_insensitive: Whether to perform case-insensitive search
        max_attempts: Maximum number of polling attempts
        
    Returns:
        Dict containing the search results with events
        
    Raises:
        APIError: If the API request fails
    """
    # First translate the natural language to UDM query
    udm_query = translate_nl_to_udm(client, text)
    
    # Then perform the UDM search
    return client.search_udm(
        query=udm_query,
        start_time=start_time,
        end_time=end_time,
        max_events=max_events,
        case_insensitive=case_insensitive,
        max_attempts=max_attempts
    ) 