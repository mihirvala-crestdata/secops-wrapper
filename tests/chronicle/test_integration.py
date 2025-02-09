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