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
"""Integration tests for Chronicle API.

These tests require valid credentials and API access.
"""
import pytest
from datetime import datetime, timedelta, timezone
from secops import SecOpsClient
from ..config import CHRONICLE_CONFIG, SERVICE_ACCOUNT_JSON
from secops.exceptions import APIError

@pytest.mark.integration
def test_chronicle_search():
    """Test Chronicle search functionality with real API."""
    client = SecOpsClient()
    chronicle = client.chronicle(**CHRONICLE_CONFIG)
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)
    
    result = chronicle.fetch_udm_search_csv(
        query="metadata.event_type = \"NETWORK_CONNECTION\"",
        start_time=start_time,
        end_time=end_time,
        fields=["timestamp", "user", "hostname", "process name"]
    )
    
    assert isinstance(result, str)
    assert "timestamp" in result  # Basic validation of CSV header 

@pytest.mark.integration
def test_chronicle_stats():
    """Test Chronicle stats search functionality with real API."""
    client = SecOpsClient(service_account_info=SERVICE_ACCOUNT_JSON)
    chronicle = client.chronicle(**CHRONICLE_CONFIG)
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)
    
    # Use a stats query format
    query = """metadata.event_type = "NETWORK_CONNECTION"
match:
    metadata.event_type
outcome:
    $count = count(metadata.id)
order:
    metadata.event_type asc"""

    validation = chronicle.validate_query(query)
    print(f"\nValidation response: {validation}")  # Debug print
    assert validation.get("queryType") == "QUERY_TYPE_STATS_QUERY"  # Note: changed assertion
    
    try:
        # Perform stats search with limited results
        result = chronicle.get_stats(
            query=query,
            start_time=start_time,
            end_time=end_time,
            max_events=10,  # Limit results for testing
            max_values=10  # Limit field values for testing
        )
        
        assert "columns" in result
        assert "rows" in result
        assert isinstance(result["total_rows"], int)
        
    except APIError as e:
        print(f"\nAPI Error details: {str(e)}")  # Debug print
        raise 

@pytest.mark.integration
def test_chronicle_udm_search():
    """Test Chronicle UDM search functionality with real API."""
    client = SecOpsClient(service_account_info=SERVICE_ACCOUNT_JSON)
    chronicle = client.chronicle(**CHRONICLE_CONFIG)
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)
    
    # Use a UDM query
    query = 'target.ip != ""'

    validation = chronicle.validate_query(query)
    print(f"\nValidation response: {validation}")  # Debug print
    assert validation.get("queryType") == "QUERY_TYPE_UDM_QUERY"
    
    try:
        # Perform UDM search with limited results
        result = chronicle.search_udm(
            query=query,
            start_time=start_time,
            end_time=end_time,
            max_events=10  # Limit results for testing
        )
        
        assert "events" in result
        assert "total_events" in result
        assert isinstance(result["total_events"], int)
        
        # Verify event structure if we got any results
        if result["events"]:
            event = result["events"][0]
            assert "event" in event
            assert "metadata" in event["event"]
        
    except APIError as e:
        print(f"\nAPI Error details: {str(e)}")  # Debug print
        raise 

@pytest.mark.integration
def test_chronicle_summarize_entity():
    """Test Chronicle entity summary functionality with real API."""
    client = SecOpsClient(service_account_info=SERVICE_ACCOUNT_JSON)
    chronicle = client.chronicle(**CHRONICLE_CONFIG)
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=30)  # Look back 30 days
    
    try:
        # Get summary for a domain
        result = chronicle.summarize_entity(
            start_time=start_time,
            end_time=end_time,
            field_path="principal.ip",
            value="153.200.135.92",
            return_alerts=True,
            include_all_udm_types=True
        )
        
        assert result.entities is not None
        if result.entities:
            entity = result.entities[0]
            assert entity.metadata.entity_type == "ASSET"
            assert "153.200.135.92" in entity.entity.get("asset", {}).get("ip", [])
            
    except APIError as e:
        print(f"\nAPI Error details: {str(e)}")  # Debug print
        raise 

@pytest.mark.integration
def test_chronicle_summarize_entities_from_query():
    """Test Chronicle entity summaries from query functionality with real API."""
    client = SecOpsClient(service_account_info=SERVICE_ACCOUNT_JSON)
    chronicle = client.chronicle(**CHRONICLE_CONFIG)
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=1)
    
    try:
        # Build query for file hash lookup
        md5 = "e17dd4eef8b4978673791ef4672f4f6a"
        query = (
            f'principal.file.md5 = "{md5}" OR '
            f'principal.process.file.md5 = "{md5}" OR '
            f'target.file.md5 = "{md5}" OR '
            f'target.process.file.md5 = "{md5}" OR '
            f'security_result.about.file.md5 = "{md5}" OR '
            f'src.file.md5 = "{md5}" OR '
            f'src.process.file.md5 = "{md5}"'
        )
        
        results = chronicle.summarize_entities_from_query(
            query=query,
            start_time=start_time,
            end_time=end_time
        )
        
        assert isinstance(results, list)
        if results:
            summary = results[0]
            assert summary.entities is not None
            if summary.entities:
                entity = summary.entities[0]
                assert entity.metadata.entity_type == "FILE"
                assert entity.entity.get("file", {}).get("md5") == md5
            
    except APIError as e:
        print(f"\nAPI Error details: {str(e)}")  # Debug print
        raise 

@pytest.mark.integration
def test_chronicle_alerts():
    """Test Chronicle alerts functionality with real API."""
    client = SecOpsClient(service_account_info=SERVICE_ACCOUNT_JSON)
    chronicle = client.chronicle(**CHRONICLE_CONFIG)
    
    # Get alerts from the last 1 day
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=1)
    
    try:
        # Use a query to get non-closed alerts
        result = chronicle.get_alerts(
            start_time=start_time,
            end_time=end_time,
            snapshot_query='feedback_summary.status != "CLOSED"',
            max_alerts=10,  # Limit to 10 alerts for testing
            max_attempts=5   # Limit polling attempts for faster test
        )
        
        # Basic validation of the response
        assert 'complete' in result
        assert result.get('complete') is True or result.get('progress') == 1
        
        # Check if we got any alerts
        alerts = result.get('alerts', {}).get('alerts', [])
        print(f"\nFound {len(alerts)} alerts")
        
        # If we have alerts, validate their structure
        if alerts:
            alert = alerts[0]
            assert 'id' in alert
            assert 'type' in alert
            assert 'createdTime' in alert
            
            # Check detection info if this is a rule detection
            if alert.get('type') == 'RULE_DETECTION' and 'detection' in alert:
                detection = alert.get('detection', [])[0]
                assert 'ruleName' in detection
                print(f"\nRule name: {detection.get('ruleName')}")
            
            # Check if alert is linked to a case
            if 'caseName' in alert:
                print(f"\nAlert is linked to case: {alert.get('caseName')}")
        
        # Validate field aggregations if present
        field_aggregations = result.get('fieldAggregations', {}).get('fields', [])
        if field_aggregations:
            assert isinstance(field_aggregations, list)
            
            # Check specific field aggregations if available
            status_field = next((f for f in field_aggregations if f.get('fieldName') == 'feedback_summary.status'), None)
            if status_field:
                print(f"\nStatus field values: {[v.get('value', {}).get('enumValue') for v in status_field.get('allValues', [])]}")
        
    except APIError as e:
        print(f"\nAPI Error details: {str(e)}")  # Debug print
        raise