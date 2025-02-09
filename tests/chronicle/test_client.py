"""Tests for Chronicle API client."""
from datetime import datetime, timezone
import pytest
from unittest.mock import Mock, patch
from secops.chronicle.client import ChronicleClient, _detect_value_type, ValueType
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
from secops.exceptions import APIError

@pytest.fixture
def chronicle_client():
    """Create a Chronicle client for testing."""
    return ChronicleClient(
        customer_id="test-customer",
        project_id="test-project"
    )

@pytest.fixture
def mock_response():
    """Create a mock API response."""
    mock = Mock()
    mock.status_code = 200
    mock.text = "timestamp,user,hostname,process_name\n2024-01-15T00:00:00Z,user1,host1,process1"
    return mock

def test_fetch_udm_search_csv(chronicle_client, mock_response):
    """Test fetching UDM search results."""
    with patch('google.auth.transport.requests.AuthorizedSession.post', return_value=mock_response):
        result = chronicle_client.fetch_udm_search_csv(
            query="metadata.event_type = \"NETWORK_CONNECTION\"",
            start_time=datetime(2024, 1, 14, 23, 7, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 15, 0, 7, tzinfo=timezone.utc),
            fields=["timestamp", "user", "hostname", "process name"]
        )
        
        assert "timestamp,user,hostname,process_name" in result
        assert "user1,host1,process1" in result

def test_fetch_udm_search_csv_error(chronicle_client):
    """Test handling of API errors."""
    error_response = Mock()
    error_response.status_code = 400
    error_response.text = "Invalid request"

    with patch('google.auth.transport.requests.AuthorizedSession.post', return_value=error_response):
        with pytest.raises(APIError) as exc_info:
            chronicle_client.fetch_udm_search_csv(
                query="invalid query",
                start_time=datetime(2024, 1, 14, 23, 7, tzinfo=timezone.utc),
                end_time=datetime(2024, 1, 15, 0, 7, tzinfo=timezone.utc),
                fields=["timestamp"]
            )
        
        assert "Chronicle API request failed" in str(exc_info.value)

def test_validate_query(chronicle_client):
    """Test query validation."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"isValid": True}

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        result = chronicle_client.validate_query("metadata.event_type = \"NETWORK_CONNECTION\"")
        assert result["isValid"] is True

def test_get_stats(chronicle_client):
    """Test stats search functionality."""
    # Mock the initial search request
    mock_search_response = Mock()
    mock_search_response.status_code = 200
    mock_search_response.json.return_value = [{
        "operation": "projects/test-project/locations/us/instances/test-instance/operations/test-operation"
    }]

    # Mock the results polling
    mock_results_response = Mock()
    mock_results_response.status_code = 200
    mock_results_response.json.return_value = [{
        "operation": {
            "done": True,
            "response": {
                "complete": True,
                "stats": {
                    "results": [
                        {
                            "column": "count",
                            "values": [{"value": {"int64Val": "42"}}]
                        },
                        {
                            "column": "hostname",
                            "values": [{"value": {"stringVal": "test-host"}}]
                        }
                    ]
                }
            }
        }
    }]

    with patch.object(chronicle_client.session, 'post', return_value=mock_search_response), \
         patch.object(chronicle_client.session, 'get', return_value=mock_results_response):
        
        result = chronicle_client.get_stats(
            query="""target.ip != ""
match:
  target.ip, principal.hostname
outcome:
  $count = count(metadata.id)
order:
  principal.hostname asc""",
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            max_events=10,
            max_values=10
        )

        assert result["total_rows"] == 1
        assert result["columns"] == ["count", "hostname"]
        assert result["rows"][0] == {"count": 42, "hostname": "test-host"}

def test_search_udm(chronicle_client):
    """Test UDM search functionality."""
    # Mock the initial search request
    mock_search_response = Mock()
    mock_search_response.status_code = 200
    mock_search_response.json.return_value = [{
        "operation": "projects/test-project/locations/us/instances/test-instance/operations/test-operation"
    }]

    # Mock the results polling
    mock_results_response = Mock()
    mock_results_response.status_code = 200
    mock_results_response.json.return_value = [{
        "operation": {
            "done": True,
            "response": {
                "complete": True,
                "events": {
                    "events": [{
                        "event": {
                            "metadata": {
                                "eventTimestamp": "2024-01-01T00:00:00Z",
                                "eventType": "NETWORK_CONNECTION"
                            },
                            "target": {
                                "ip": "192.168.1.1",
                                "hostname": "test-host"
                            }
                        }
                    }]
                }
            }
        }
    }]

    with patch.object(chronicle_client.session, 'post', return_value=mock_search_response), \
         patch.object(chronicle_client.session, 'get', return_value=mock_results_response):
        
        result = chronicle_client.search_udm(
            query='target.ip != ""',
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            max_events=10
        )

        assert "events" in result
        assert "total_events" in result
        assert result["total_events"] == 1
        assert result["events"][0]["event"]["target"]["ip"] == "192.168.1.1"

def test_summarize_entity(chronicle_client):
    """Test entity summary functionality."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "entities": [{
            "name": "test-entity",
            "metadata": {
                "entityType": "DOMAIN_NAME",
                "interval": {
                    "startTime": "2024-01-01T00:00:00Z",
                    "endTime": "2024-01-02T00:00:00Z"
                }
            },
            "entity": {
                "domain": {
                    "name": "test.com",
                    "firstSeenTime": "2024-01-01T00:00:00Z",
                    "lastSeenTime": "2024-01-02T00:00:00Z"
                }
            },
            "metric": {
                "firstSeen": "2024-01-01T00:00:00Z",
                "lastSeen": "2024-01-02T00:00:00Z"
            }
        }],
        "timeline": {
            "buckets": [{}],
            "bucketSize": "3600s"
        },
        "widgetMetadata": {
            "uri": "test-uri",
            "detections": 1,
            "total": 100
        }
    }

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        result = chronicle_client.summarize_entity(
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            field_path="domain.name",
            value="test.com",
            value_type="DOMAIN_NAME"
        )

        assert len(result.entities) == 1
        assert result.entities[0].name == "test-entity"
        assert result.entities[0].metadata.entity_type == "DOMAIN_NAME"
        assert result.widget_metadata.detections == 1
        assert result.widget_metadata.total == 100

def test_summarize_entities_from_query(chronicle_client):
    """Test entity summaries from query functionality."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "entitySummaries": [{
            "entity": [{
                "name": "test-entity",
                "metadata": {
                    "entityType": "FILE",
                    "interval": {
                        "startTime": "2024-01-01T00:00:00Z",
                        "endTime": "2024-01-02T00:00:00Z"
                    }
                },
                "entity": {
                    "file": {
                        "md5": "e17dd4eef8b4978673791ef4672f4f6a",
                        "firstSeenTime": "2024-01-01T00:00:00Z",
                        "lastSeenTime": "2024-01-02T00:00:00Z"
                    }
                },
                "metric": {
                    "firstSeen": "2024-01-01T00:00:00Z",
                    "lastSeen": "2024-01-02T00:00:00Z"
                }
            }]
        }]
    }

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        results = chronicle_client.summarize_entities_from_query(
            query='principal.file.md5 = "e17dd4eef8b4978673791ef4672f4f6a"',
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc)
        )

        assert len(results) == 1
        assert len(results[0].entities) == 1
        entity = results[0].entities[0]
        assert entity.metadata.entity_type == "FILE"
        assert entity.entity["file"]["md5"] == "e17dd4eef8b4978673791ef4672f4f6a"

def test_summarize_entity_file(chronicle_client):
    """Test entity summary functionality for files."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "entities": [{
            "name": "test-entity",
            "metadata": {
                "entityType": "FILE",
                "interval": {
                    "startTime": "2024-01-01T00:00:00Z",
                    "endTime": "2024-01-02T00:00:00Z"
                }
            },
            "entity": {
                "file": {
                    "md5": "e17dd4eef8b4978673791ef4672f4f6a",
                    "firstSeenTime": "2024-01-01T00:00:00Z",
                    "lastSeenTime": "2024-01-02T00:00:00Z"
                }
            },
            "metric": {
                "firstSeen": "2024-01-01T00:00:00Z",
                "lastSeen": "2024-01-02T00:00:00Z"
            }
        }],
        "alertCounts": [
            {
                "rule": "Test Rule",
                "count": "42"
            }
        ],
        "widgetMetadata": {
            "uri": "test-uri",
            "detections": 48,
            "total": 69
        }
    }

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        result = chronicle_client.summarize_entity(
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            field_path="target.file.md5",
            value="e17dd4eef8b4978673791ef4672f4f6a"
        )

        assert len(result.entities) == 1
        assert result.entities[0].metadata.entity_type == "FILE"
        assert result.entities[0].entity["file"]["md5"] == "e17dd4eef8b4978673791ef4672f4f6a"
        assert len(result.alert_counts) == 1
        assert result.alert_counts[0].rule == "Test Rule"
        assert result.alert_counts[0].count == 42
        assert result.widget_metadata.detections == 48
        assert result.widget_metadata.total == 69

def test_detect_value_type():
    """Test value type detection."""
    # Test IP address detection
    field_path, value_type = _detect_value_type("192.168.1.1")
    assert field_path == "principal.ip"
    assert value_type is None

    # Test invalid IP
    field_path, value_type = _detect_value_type("256.256.256.256")
    assert field_path is None
    assert value_type is None

    # Test MD5 hash detection
    field_path, value_type = _detect_value_type("d41d8cd98f00b204e9800998ecf8427e")
    assert field_path == "target.file.md5"
    assert value_type is None

    # Test SHA1 hash detection
    field_path, value_type = _detect_value_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert field_path == "target.file.sha1"
    assert value_type is None

    # Test SHA256 hash detection
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    field_path, value_type = _detect_value_type(sha256)
    assert field_path == "target.file.sha256"
    assert value_type is None

    # Test domain detection
    field_path, value_type = _detect_value_type("example.com")
    assert field_path is None
    assert value_type == "DOMAIN_NAME"

    field_path, value_type = _detect_value_type("sub.example.com")
    assert field_path is None
    assert value_type == "DOMAIN_NAME"

    # Test email detection
    field_path, value_type = _detect_value_type("user@example.com")
    assert field_path is None
    assert value_type == "EMAIL"

    # Test MAC address detection
    field_path, value_type = _detect_value_type("00:11:22:33:44:55")
    assert field_path is None
    assert value_type == "MAC"

    field_path, value_type = _detect_value_type("00-11-22-33-44-55")
    assert field_path is None
    assert value_type == "MAC"

    # Test hostname detection
    field_path, value_type = _detect_value_type("host-name-123")
    assert field_path is None
    assert value_type == "HOSTNAME"

def test_summarize_entity_auto_detection(chronicle_client):
    """Test entity summary with automatic type detection."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "entities": [{
            "name": "test-entity",
            "metadata": {
                "entityType": "FILE",
                "interval": {
                    "startTime": "2024-01-01T00:00:00Z",
                    "endTime": "2024-01-02T00:00:00Z"
                }
            },
            "entity": {
                "file": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "firstSeenTime": "2024-01-01T00:00:00Z",
                    "lastSeenTime": "2024-01-02T00:00:00Z"
                }
            },
            "metric": {
                "firstSeen": "2024-01-01T00:00:00Z",
                "lastSeen": "2024-01-02T00:00:00Z"
            }
        }]
    }

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        # Test MD5 auto-detection
        result = chronicle_client.summarize_entity(
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            value="d41d8cd98f00b204e9800998ecf8427e"
        )
        assert len(result.entities) == 1
        assert result.entities[0].metadata.entity_type == "FILE"

def test_summarize_entity_type_override(chronicle_client):
    """Test entity summary with type override."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "entities": [{
            "name": "test-entity",
            "metadata": {
                "entityType": "DOMAIN_NAME",
                "interval": {
                    "startTime": "2024-01-01T00:00:00Z",
                    "endTime": "2024-01-02T00:00:00Z"
                }
            },
            "entity": {
                "domain": {
                    "name": "example.com"
                }
            },
            "metric": {
                "firstSeen": "2024-01-01T00:00:00Z",
                "lastSeen": "2024-01-02T00:00:00Z"
            }
        }]
    }

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        # Test override of auto-detection
        result = chronicle_client.summarize_entity(
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            value="example.com",
            field_path="custom.field.path"  # Override auto-detection
        )
        assert len(result.entities) == 1
        assert result.entities[0].metadata.entity_type == "DOMAIN_NAME"

def test_summarize_entity_invalid_value(chronicle_client):
    """Test entity summary with invalid value."""
    with pytest.raises(ValueError) as exc_info:
        chronicle_client.summarize_entity(
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            value="!@#$%^"  # Invalid value that won't match any pattern
        )
    assert "Could not determine type for value" in str(exc_info.value)

def test_summarize_entity_edge_cases(chronicle_client):
    """Test entity summary edge cases."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"entities": []}

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        # Test very long domain name
        result = chronicle_client.summarize_entity(
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            value="very-long-subdomain.example.com"
        )
        assert len(result.entities) == 0

        # Test IP with leading zeros
        result = chronicle_client.summarize_entity(
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            value="192.168.001.001"
        )
        assert len(result.entities) == 0

def test_summarize_entity_all_types(chronicle_client):
    """Test entity summary with all supported types."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"entities": []}

    test_values = {
        "IP": "192.168.1.1",
        "MD5": "d41d8cd98f00b204e9800998ecf8427e",
        "SHA1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "SHA256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Domain": "example.com",
        "Email": "user@example.com",
        "MAC": "00:11:22:33:44:55",
        "Hostname": "test-host-123"
    }

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        for type_name, value in test_values.items():
            result = chronicle_client.summarize_entity(
                start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
                end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
                value=value
            )
            assert isinstance(result, EntitySummary), f"Failed for type: {type_name}" 