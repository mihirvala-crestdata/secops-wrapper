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
"""UDM search functionality for Chronicle."""

from datetime import datetime
import time
from typing import Dict, Any
from secops.exceptions import APIError
import requests

def search_udm(
    client,
    query: str,
    start_time: datetime,
    end_time: datetime,
    max_events: int = 10000,
    case_insensitive: bool = True,
    max_attempts: int = 30,
    timeout: int = 30,
    debug: bool = False
) -> Dict[str, Any]:
    """Perform a UDM search query.
    
    Args:
        client: ChronicleClient instance
        query: The UDM search query
        start_time: Search start time
        end_time: Search end time
        max_events: Maximum events to return
        case_insensitive: Whether to perform case-insensitive search
        max_attempts: Maximum number of polling attempts (default: 30)
        timeout: Timeout in seconds for each API request (default: 30)
        debug: Print debug information during execution
        
    Returns:
        Dict containing the search results with events
        
    Raises:
        APIError: If the API request fails
    """
    url = f"{client.base_url}/{client.instance_id}/legacy:legacyFetchUdmSearchView"

    payload = {
        "baselineQuery": query,
        "baselineTimeRange": {
            "startTime": start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "endTime": end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        },
        "caseInsensitive": case_insensitive,
        "returnOperationIdOnly": True,
        "eventList": {
            "maxReturnedEvents": max_events
        }
    }

    # Start the search operation
    if debug:
        print(f"Initiating UDM search: {query}")
        print(f"Time range: {start_time.isoformat()} to {end_time.isoformat()}")
    
    try:
        response = client.session.post(url, json=payload, timeout=timeout)
        if response.status_code != 200:
            error_msg = f"Error initiating search: Status {response.status_code}, Response: {response.text}"
            if debug:
                print(f"Error: {error_msg}")
            raise APIError(error_msg)
    except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
        error_msg = f"Timeout initiating search: {str(e)}"
        if debug:
            print(f"Error: {error_msg}")
        raise APIError(error_msg)

    try:
        operation = response.json()
        if debug:
            print(f"Initial search response: {operation}")
    except ValueError:
        error_msg = "Invalid JSON response from search API"
        if debug:
            print(f"Error: {error_msg}")
        raise APIError(error_msg)

    # Extract operation ID from response
    try:
        if isinstance(operation, list):
            operation_id = operation[0].get("operation")
        else:
            operation_id = operation.get("operation") or operation.get("name")
    except Exception as e:
        error_msg = f"Error extracting operation ID. Response: {operation}, Error: {str(e)}"
        if debug:
            print(f"Error: {error_msg}")
        raise APIError(error_msg)

    if not operation_id:
        error_msg = f"No operation ID found in response: {operation}"
        if debug:
            print(f"Error: {error_msg}")
        raise APIError(error_msg)

    if debug:
        print(f"Operation ID: {operation_id}")

    # Poll for results using the full operation ID path
    results_url = f"{client.base_url}/{operation_id}:streamSearch"
    attempt = 0
    
    while attempt < max_attempts:
        if debug:
            print(f"Polling attempt {attempt+1}/{max_attempts}")
        
        try:
            results_response = client.session.get(results_url, timeout=timeout)
            if results_response.status_code != 200:
                if debug:
                    print(f"Error response: {results_response.status_code}, {results_response.text}")
                # Don't immediately fail, try again
                attempt += 1
                time.sleep(1)
                continue

            results = results_response.json()
            if debug:
                print(f"Poll response: {results}")
                
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
            # If we time out, just continue to the next attempt
            if debug:
                print(f"Timeout during polling: {str(e)}")
            attempt += 1
            time.sleep(1)
            continue
        except ValueError as e:
            # If we can't parse the JSON, try again
            if debug:
                print(f"JSON parsing error: {str(e)}")
            attempt += 1
            time.sleep(1)
            continue

        if isinstance(results, list):
            results = results[0]

        # Check both possible paths for completion status
        done = (
            results.get("done") or  # Check top level
            results.get("operation", {}).get("done") or  # Check under operation
            results.get("response", {}).get("complete")  # Check under response
        )

        if done:
            if debug:
                print("Search completed successfully")
                
            events = (
                results.get("response", {}).get("events", {}).get("events", []) or
                results.get("operation", {}).get("response", {}).get("events", {}).get("events", [])
            )
            
            if debug:
                print(f"Found {len(events)} events")
                
            return {"events": events, "total_events": len(events)}

        attempt += 1
        time.sleep(1)
    
    if debug:
        print(f"Search exceeded maximum attempts ({max_attempts}), returning empty result")
        
    # If we've reached max attempts, return an empty result rather than raising an error
    return {"events": [], "total_events": 0} 