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
"""Statistics functionality for Chronicle searches."""
from datetime import datetime
import time
from typing import Dict, Any
from secops.exceptions import APIError

def get_stats(
    client,
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
        client: ChronicleClient instance
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
        },
        "fieldAggregations": {
            "maxValuesPerField": max_values
        },
        "generateAiOverview": True
    }

    # Start the search operation
    response = client.session.post(url, json=payload)
    if response.status_code != 200:
        raise APIError(
            f"Error initiating search: Status {response.status_code}, "
            f"Response: {response.text}"
        )

    operation = response.json()

    # Extract operation ID from response
    try:
        if isinstance(operation, list):
            operation_id = operation[0].get("operation")
        else:
            operation_id = operation.get("operation") or operation.get("name")
    except Exception as e:
        raise APIError(
            f"Error extracting operation ID. Response: {operation}, Error: {str(e)}"
        )

    if not operation_id:
        raise APIError(f"No operation ID found in response: {operation}")

    # Poll for results using the full operation ID path
    results_url = f"{client.base_url}/{operation_id}:streamSearch"
    attempt = 0
    
    while attempt < max_attempts:
        results_response = client.session.get(results_url)
        if results_response.status_code != 200:
            raise APIError(f"Error fetching results: {results_response.text}")

        results = results_response.json()

        if isinstance(results, list):
            results = results[0]

        # Check both possible paths for completion status
        done = (
            results.get("done") or  # Check top level
            results.get("operation", {}).get("done") or  # Check under operation
            results.get("response", {}).get("complete")  # Check under response
        )

        if done:
            # Check both possible paths for stats
            stats = (
                results.get("response", {}).get("stats") or  # Check under response
                results.get("operation", {}).get("response", {}).get("stats")  # Check under operation.response
            )
            if stats:
                # Process the stats results directly here for better control
                return process_stats_results(stats)
            else:
                raise APIError("No stats found in completed response")

        attempt += 1
        time.sleep(1)
    
    raise APIError(f"Search timed out after {max_attempts} attempts")

def process_stats_results(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Process stats search results.
    
    Args:
        stats: Stats search results from API
        
    Returns:
        Processed statistics
    """
    processed_results = {
        "total_rows": 0,
        "columns": [],
        "rows": []
    }
    
    # Return early if no results
    if not stats or "results" not in stats:
        return processed_results
    
    # Extract columns
    columns = []
    column_data = {}
    
    for col_data in stats["results"]:
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
        max_rows = max(len(column_data[col]) for col in columns) if column_data else 0
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