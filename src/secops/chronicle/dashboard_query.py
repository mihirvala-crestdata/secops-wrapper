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
"""
Module for Google SecOps Dashboard query.

This module provides functions to execute and get dashboard query.
"""

import json
from secops.chronicle.models import InputInterval
from typing import Any, Dict, List, Optional, Union

from secops.exceptions import APIError


def execute_query(
    client,
    query: str,
    interval: Union[InputInterval, Dict[str, Any], str],
    filters: Optional[Union[List[Dict[str, Any]], str]] = None,
    clear_cache: Optional[bool] = None,
) -> Dict[str, Any]:
    """Execute a dashboard query and retrieve results.

    Args:
        client: ChronicleClient instance
        query: The UDM search query to execute
        interval: The time interval for the query
        filters: Filters to apply to the query
        clear_cache: Flag to read from database instead of cache

    Returns:
        Dictionary containing query results
    """
    url = f"{client.base_url}/{client.instance_id}/dashboardQueries:execute"

    try:
        if isinstance(interval, str):
            interval = json.loads(interval)
        if filters and isinstance(filters, str):
            filters = json.loads(filters)
            if not isinstance(filters, list):
                filters = [filters]
    except ValueError as e:
        raise APIError(
            f"Failed to parse JSON. Must be a valid JSON string: {e}"
        ) from e

    if isinstance(interval, dict):
        interval = InputInterval.from_dict(interval)

    payload = {"query": {"query": query, "input": interval.to_dict()}}

    if clear_cache is not None:
        payload["clearCache"] = clear_cache
    if filters:
        payload["filters"] = filters

    response = client.session.post(url, json=payload)

    if response.status_code != 200:
        raise APIError(
            f"Failed to execute query: Status {response.status_code}, "
            f"Response: {response.text}"
        )

    return response.json()


def get_execute_query(client, query_id: str) -> Dict[str, Any]:
    """Get a dashboard query details.

    Args:
        client: ChronicleClient instance
        query_id: ID of the query to retrieve details

    Returns:
        Dictionary containing query details
    """
    if query_id.startswith("projects/"):
        query_id = query_id.split("/")[-1]

    url = f"{client.base_url}/{client.instance_id}/dashboardQueries/{query_id}"

    response = client.session.get(url)

    if response.status_code != 200:
        raise APIError(
            f"Failed to get query: Status {response.status_code}, "
            f"Response: {response.text}"
        )

    return response.json()
