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
"""Tests for Chronicle log ingestion functionality."""
import base64
import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

from secops.chronicle.client import ChronicleClient
from secops.chronicle.log_ingest import (
    ingest_log,
    get_or_create_forwarder,
    list_forwarders,
    create_forwarder,
    extract_forwarder_id
)
from secops.exceptions import APIError


@pytest.fixture
def chronicle_client():
    """Create a Chronicle client for testing."""
    return ChronicleClient(
        customer_id="test-customer",
        project_id="test-project",
        region="us"
    )


@pytest.fixture
def mock_forwarder_response():
    """Create a mock forwarder API response."""
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = {
        "name": "projects/test-project/locations/us/instances/test-customer/forwarders/test-forwarder-id",
        "displayName": "Wrapper-SDK-Forwarder",
        "createTime": "2025-01-01T00:00:00.000Z",
        "updateTime": "2025-01-01T00:00:00.000Z",
        "config": {
            "uploadCompression": False,
            "metadata": {}
        }
    }
    return mock


@pytest.fixture
def mock_forwarders_list_response():
    """Create a mock forwarders list API response."""
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = {
        "forwarders": [
            {
                "name": "projects/test-project/locations/us/instances/test-customer/forwarders/test-forwarder-id",
                "displayName": "Wrapper-SDK-Forwarder",
                "createTime": "2025-01-01T00:00:00.000Z",
                "updateTime": "2025-01-01T00:00:00.000Z",
                "config": {
                    "uploadCompression": False,
                    "metadata": {}
                }
            }
        ]
    }
    return mock


@pytest.fixture
def mock_ingest_response():
    """Create a mock log ingestion API response."""
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = {
        "operation": "projects/test-project/locations/us/operations/operation-id"
    }
    return mock


def test_extract_forwarder_id():
    """Test extracting forwarder ID from full resource name."""
    # Test with full resource name
    resource_name = "projects/test-project/locations/us/instances/test-customer/forwarders/test-forwarder-id"
    assert extract_forwarder_id(resource_name) == "test-forwarder-id"
    
    # Test with just ID
    assert extract_forwarder_id("test-forwarder-id") == "test-forwarder-id"
    
    # Test with empty string
    with pytest.raises(ValueError):
        extract_forwarder_id("")
    
    # Test with invalid format
    with pytest.raises(ValueError):
        extract_forwarder_id("/")


def test_create_forwarder(chronicle_client, mock_forwarder_response):
    """Test creating a forwarder."""
    with patch.object(chronicle_client.session, 'post', return_value=mock_forwarder_response):
        result = create_forwarder(
            client=chronicle_client,
            display_name="Wrapper-SDK-Forwarder"
        )
        
        assert result["name"] == "projects/test-project/locations/us/instances/test-customer/forwarders/test-forwarder-id"
        assert result["displayName"] == "Wrapper-SDK-Forwarder"


def test_create_forwarder_error(chronicle_client):
    """Test error handling when creating a forwarder."""
    error_response = Mock()
    error_response.status_code = 400
    error_response.text = "Invalid request"
    
    with patch.object(chronicle_client.session, 'post', return_value=error_response):
        with pytest.raises(APIError, match="Failed to create forwarder"):
            create_forwarder(
                client=chronicle_client,
                display_name="Wrapper-SDK-Forwarder"
            )


def test_list_forwarders(chronicle_client, mock_forwarders_list_response):
    """Test listing forwarders."""
    with patch.object(chronicle_client.session, 'get', return_value=mock_forwarders_list_response):
        result = list_forwarders(client=chronicle_client)
        
        assert len(result["forwarders"]) == 1
        assert result["forwarders"][0]["displayName"] == "Wrapper-SDK-Forwarder"


def test_list_forwarders_error(chronicle_client):
    """Test error handling when listing forwarders."""
    error_response = Mock()
    error_response.status_code = 400
    error_response.text = "Invalid request"
    
    with patch.object(chronicle_client.session, 'get', return_value=error_response):
        with pytest.raises(APIError, match="Failed to list forwarders"):
            list_forwarders(client=chronicle_client)


def test_get_or_create_forwarder_existing(chronicle_client, mock_forwarders_list_response):
    """Test getting an existing forwarder."""
    with patch.object(chronicle_client.session, 'get', return_value=mock_forwarders_list_response):
        result = get_or_create_forwarder(
            client=chronicle_client,
            display_name="Wrapper-SDK-Forwarder"
        )
        
        assert result["displayName"] == "Wrapper-SDK-Forwarder"


def test_get_or_create_forwarder_new(chronicle_client, mock_forwarders_list_response, mock_forwarder_response):
    """Test creating a new forwarder when one doesn't exist."""
    # Empty list of forwarders
    empty_response = Mock()
    empty_response.status_code = 200
    empty_response.json.return_value = {"forwarders": []}
    
    with patch.object(chronicle_client.session, 'get', return_value=empty_response), \
         patch.object(chronicle_client.session, 'post', return_value=mock_forwarder_response):
        result = get_or_create_forwarder(
            client=chronicle_client,
            display_name="Wrapper-SDK-Forwarder"
        )
        
        assert result["displayName"] == "Wrapper-SDK-Forwarder"


def test_ingest_log_basic(chronicle_client, mock_forwarders_list_response, mock_ingest_response):
    """Test basic log ingestion functionality."""
    test_log = {"test": "log", "message": "Test message"}
    
    with patch.object(chronicle_client.session, 'get', return_value=mock_forwarders_list_response), \
         patch.object(chronicle_client.session, 'post', return_value=mock_ingest_response), \
         patch('secops.chronicle.log_ingest.is_valid_log_type', return_value=True):
        result = ingest_log(
            client=chronicle_client,
            log_type="OKTA",
            log_message=json.dumps(test_log)
        )
        
        assert "operation" in result
        assert result["operation"] == "projects/test-project/locations/us/operations/operation-id"


def test_ingest_log_with_timestamps(chronicle_client, mock_forwarders_list_response, mock_ingest_response):
    """Test log ingestion with custom timestamps."""
    test_log = {"test": "log", "message": "Test message"}
    log_entry_time = datetime.now(timezone.utc) - timedelta(hours=1)
    collection_time = datetime.now(timezone.utc)
    
    with patch.object(chronicle_client.session, 'get', return_value=mock_forwarders_list_response), \
         patch.object(chronicle_client.session, 'post', return_value=mock_ingest_response), \
         patch('secops.chronicle.log_ingest.is_valid_log_type', return_value=True):
        result = ingest_log(
            client=chronicle_client,
            log_type="OKTA",
            log_message=json.dumps(test_log),
            log_entry_time=log_entry_time,
            collection_time=collection_time
        )
        
        assert "operation" in result


def test_ingest_log_invalid_timestamps(chronicle_client):
    """Test log ingestion with invalid timestamps (collection before entry)."""
    test_log = {"test": "log", "message": "Test message"}
    log_entry_time = datetime.now(timezone.utc)
    collection_time = datetime.now(timezone.utc) - timedelta(hours=1)  # Earlier than entry time
    
    with pytest.raises(ValueError, match="Collection time must be same or after log entry time"):
        ingest_log(
            client=chronicle_client,
            log_type="OKTA",
            log_message=json.dumps(test_log),
            log_entry_time=log_entry_time,
            collection_time=collection_time
        )


def test_ingest_log_invalid_log_type(chronicle_client):
    """Test log ingestion with invalid log type."""
    test_log = {"test": "log", "message": "Test message"}
    
    with patch('secops.chronicle.log_ingest.is_valid_log_type', return_value=False):
        with pytest.raises(ValueError, match="Invalid log type"):
            ingest_log(
                client=chronicle_client,
                log_type="INVALID_LOG_TYPE",
                log_message=json.dumps(test_log)
            )


def test_ingest_log_force_log_type(chronicle_client, mock_forwarders_list_response, mock_ingest_response):
    """Test log ingestion with forced log type."""
    test_log = {"test": "log", "message": "Test message"}
    
    with patch.object(chronicle_client.session, 'get', return_value=mock_forwarders_list_response), \
         patch.object(chronicle_client.session, 'post', return_value=mock_ingest_response), \
         patch('secops.chronicle.log_ingest.is_valid_log_type', return_value=False):
        result = ingest_log(
            client=chronicle_client,
            log_type="CUSTOM_LOG_TYPE",
            log_message=json.dumps(test_log),
            force_log_type=True
        )
        
        assert "operation" in result


def test_ingest_log_with_custom_forwarder(chronicle_client, mock_ingest_response):
    """Test log ingestion with a custom forwarder ID."""
    test_log = {"test": "log", "message": "Test message"}
    
    with patch.object(chronicle_client.session, 'post', return_value=mock_ingest_response), \
         patch('secops.chronicle.log_ingest.is_valid_log_type', return_value=True):
        result = ingest_log(
            client=chronicle_client,
            log_type="OKTA",
            log_message=json.dumps(test_log),
            forwarder_id="custom-forwarder-id"
        )
        
        assert "operation" in result


def test_ingest_xml_log(chronicle_client, mock_forwarders_list_response, mock_ingest_response):
    """Test ingesting an XML log."""
    xml_log = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
        <EventID>4624</EventID>
        <TimeCreated SystemTime='2025-03-23T14:47:00.647937Z'/>
        <Computer>WINSERVER.example.com</Computer>
    </System>
    <EventData>
        <Data Name='TargetUserName'>TestUser</Data>
        <Data Name='LogonType'>3</Data>
    </EventData>
</Event>"""
    
    with patch.object(chronicle_client.session, 'get', return_value=mock_forwarders_list_response), \
         patch.object(chronicle_client.session, 'post', return_value=mock_ingest_response), \
         patch('secops.chronicle.log_ingest.is_valid_log_type', return_value=True):
        result = ingest_log(
            client=chronicle_client,
            log_type="WINEVTLOG_XML",
            log_message=xml_log
        )
        
        assert "operation" in result
        assert result["operation"] == "projects/test-project/locations/us/operations/operation-id" 