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
    AlertCount,
    CaseList
)
from secops.exceptions import APIError
import time

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

def test_list_iocs(chronicle_client):
    """Test listing IoCs."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "matches": [
            {
                "artifactIndicator": {"domain": "malicious.com"},
                "sources": ["Mandiant"],
                "categories": ["malware"],
                "assetIndicators": [
                    {"namespace": "test", "hostname": "infected-host"}
                ],
            }
        ],
        "more_data_available": False
    }

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        result = chronicle_client.list_iocs(
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc)
        )
        
        assert result["matches"][0]["artifactIndicator"]["domain"] == "malicious.com"
        assert not result["more_data_available"]

def test_list_iocs_error(chronicle_client):
    """Test error handling when listing IoCs."""
    mock_response = Mock()
    mock_response.status_code = 400
    mock_response.text = "Invalid request"

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        with pytest.raises(APIError, match="Failed to list IoCs"):
            chronicle_client.list_iocs(
                start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
                end_time=datetime(2024, 1, 2, tzinfo=timezone.utc)
            ) 

def test_get_cases(chronicle_client):
    """Test getting case details."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "cases": [
            {
                "id": "case-123",
                "displayName": "Test Case",
                "stage": "Investigation",
                "priority": "PRIORITY_HIGH",
                "status": "OPEN",
                "soarPlatformInfo": {
                    "caseId": "soar-123",
                    "responsePlatformType": "RESPONSE_PLATFORM_TYPE_SIEMPLIFY"
                }
            }
        ]
    }

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        result = chronicle_client.get_cases(["case-123"])
        
        assert isinstance(result, CaseList)
        case = result.get_case("case-123")
        assert case.display_name == "Test Case"
        assert case.priority == "PRIORITY_HIGH"
        assert case.soar_platform_info.case_id == "soar-123"

def test_get_cases_filtering(chronicle_client):
    """Test CaseList filtering methods."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "cases": [
            {
                "id": "case-1",
                "priority": "PRIORITY_HIGH",
                "status": "OPEN",
                "stage": "Investigation"
            },
            {
                "id": "case-2", 
                "priority": "PRIORITY_MEDIUM",
                "status": "CLOSED",
                "stage": "Triage"
            }
        ]
    }

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        result = chronicle_client.get_cases(["case-1", "case-2"])
        
        high_priority = result.filter_by_priority("PRIORITY_HIGH")
        assert len(high_priority) == 1
        assert high_priority[0].id == "case-1"

        open_cases = result.filter_by_status("OPEN")
        assert len(open_cases) == 1
        assert open_cases[0].id == "case-1"

def test_get_cases_error(chronicle_client):
    """Test error handling when getting cases."""
    mock_response = Mock()
    mock_response.status_code = 400
    mock_response.text = "Invalid request"

    with patch.object(chronicle_client.session, 'get', return_value=mock_response):
        with pytest.raises(APIError, match="Failed to get cases"):
            chronicle_client.get_cases(["invalid-id"])

def test_get_cases_limit(chronicle_client):
    """Test limiting the number of cases returned."""
    with pytest.raises(ValueError, match="Maximum of 1000 cases can be retrieved in a batch"):
        chronicle_client.get_cases(["case-id"] * 1001)

def test_get_alerts(chronicle_client):
    """Test getting alerts."""
    # First response with in-progress status
    initial_response = Mock()
    initial_response.status_code = 200
    initial_response.iter_lines.return_value = [
        b'{"progress": 0.057142861187458038, "validBaselineQuery": true, "validSnapshotQuery": true}'
    ]
    
    # Second response with completed results
    complete_response = Mock()
    complete_response.status_code = 200
    complete_response.iter_lines.return_value = [
        b'{"progress": 1, "complete": true, "validBaselineQuery": true, "baselineAlertsCount": 1, "validSnapshotQuery": true, "filteredAlertsCount": 1,',
        b'"alerts": {"alerts": [{"type": "RULE_DETECTION", "detection": [{"ruleName": "TEST_RULE", "description": "Test Rule", "ruleId": "rule-123"}],',
        b'"createdTime": "2025-03-09T15:26:10.248291Z", "id": "alert-123", "caseName": "case-123",',
        b'"feedbackSummary": {"status": "OPEN", "priority": "PRIORITY_MEDIUM", "severityDisplay": "Medium"}}]},',
        b'"fieldAggregations": {"fields": [{"fieldName": "detection.rule_name", "baselineAlertCount": 1, "alertCount": 1, "valueCount": 1,',
        b'"allValues": [{"value": {"stringValue": "TEST_RULE"}, "baselineAlertCount": 1, "alertCount": 1}]}]}}'
    ]

    # Mock the sleep function to prevent actual waiting
    with patch('time.sleep'), patch.object(chronicle_client.session, 'get', side_effect=[initial_response, complete_response]):
        result = chronicle_client.get_alerts(
            start_time=datetime(2025, 3, 8, tzinfo=timezone.utc),
            end_time=datetime(2025, 3, 9, tzinfo=timezone.utc),
            snapshot_query='feedback_summary.status != "CLOSED"',
            max_alerts=10,
            poll_interval=0.001  # Use a very small interval for testing
        )
        
        # Check the key parts of the response
        assert result.get('complete') is True
        assert result.get('validBaselineQuery') is True
        assert result.get('filteredAlertsCount') == 1
        
        # Check alert details
        alerts = result.get('alerts', {}).get('alerts', [])
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.get('id') == 'alert-123'
        assert alert.get('caseName') == 'case-123'
        assert alert.get('feedbackSummary', {}).get('status') == 'OPEN'
        assert alert.get('detection')[0].get('ruleName') == 'TEST_RULE'
        
        # Check field aggregations
        field_aggregations = result.get('fieldAggregations', {}).get('fields', [])
        assert len(field_aggregations) > 0
        rule_name_field = next((f for f in field_aggregations if f.get('fieldName') == 'detection.rule_name'), None)
        assert rule_name_field is not None
        assert rule_name_field.get('alertCount') == 1

def test_get_alerts_error(chronicle_client):
    """Test error handling for get_alerts."""
    error_response = Mock()
    error_response.status_code = 400
    error_response.text = "Invalid query syntax"
    
    with patch.object(chronicle_client.session, 'get', return_value=error_response):
        with pytest.raises(APIError, match="Failed to get alerts: Invalid query syntax"):
            chronicle_client.get_alerts(
                start_time=datetime(2025, 3, 8, tzinfo=timezone.utc),
                end_time=datetime(2025, 3, 9, tzinfo=timezone.utc)
            )

def test_get_alerts_json_parsing(chronicle_client):
    """Test handling of streaming response and JSON parsing."""
    response = Mock()
    response.status_code = 200
    # Simulate response line with a trailing comma
    response.iter_lines.return_value = [
        b'{"progress": 1, "complete": true,"alerts": {"alerts": [{"id": "alert-1"},{"id": "alert-2"},]},"fieldAggregations": {"fields": []}}'
    ]
    
    # Mock the sleep function to prevent actual waiting
    with patch('time.sleep'), patch.object(chronicle_client.session, 'get', return_value=response):
        result = chronicle_client.get_alerts(
            start_time=datetime(2025, 3, 8, tzinfo=timezone.utc),
            end_time=datetime(2025, 3, 9, tzinfo=timezone.utc),
            max_attempts=1  # Only make one request
        )
        
        # Verify the response was properly parsed despite formatting issues
        assert result.get('complete') is True
        alerts = result.get('alerts', {}).get('alerts', [])
        assert len(alerts) == 2
        assert alerts[0].get('id') == 'alert-1'
        assert alerts[1].get('id') == 'alert-2'

def test_get_alerts_parameters(chronicle_client):
    """Test that parameters are correctly set in the request."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.iter_lines.return_value = [b'{"progress": 1, "complete": true}']
    
    with patch('time.sleep'), patch.object(chronicle_client.session, 'get', return_value=mock_response) as mock_get:
        start_time = datetime(2025, 3, 8, tzinfo=timezone.utc)
        end_time = datetime(2025, 3, 9, tzinfo=timezone.utc)
        snapshot_query = 'feedback_summary.status = "OPEN"'
        baseline_query = 'detection.rule_id = "rule-123"'
        max_alerts = 50
        enable_cache = False
        
        chronicle_client.get_alerts(
            start_time=start_time,
            end_time=end_time,
            snapshot_query=snapshot_query,
            baseline_query=baseline_query,
            max_alerts=max_alerts,
            enable_cache=enable_cache,
            max_attempts=1  # Only make one request
        )
        
        # Verify that the correct parameters were sent
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        
        # Check URL and parameters
        params = kwargs.get('params', {})
        assert params.get('timeRange.startTime') == start_time.isoformat()
        assert params.get('timeRange.endTime') == end_time.isoformat()
        assert params.get('snapshotQuery') == snapshot_query
        assert params.get('baselineQuery') == baseline_query
        assert params.get('alertListOptions.maxReturnedAlerts') == max_alerts
        assert params.get('enableCache') == "ALERTS_FEATURE_PREFERENCE_DISABLED"

def test_get_alerts_json_processing(chronicle_client):
    """Test processing of streaming JSON response with complex structure."""
    response = Mock()
    response.status_code = 200
    # Simulate a complex JSON response with nested structures matching the real API
    response.iter_lines.return_value = [
        b'{"progress": 1, "complete": true, "validBaselineQuery": true, "baselineAlertsCount": 2, "validSnapshotQuery": true, "filteredAlertsCount": 2, '
        b'"alerts": {"alerts": ['
        b'{"type": "RULE_DETECTION", "detection": [{"ruleName": "RULE1", "ruleId": "rule-1", "alertState": "ALERTING", "detectionFields": [{"key": "hostname", "value": "host1"}]}], "id": "alert-1", "createdTime": "2025-03-01T00:00:00Z"},'
        b'{"type": "RULE_DETECTION", "detection": [{"ruleName": "RULE2", "ruleId": "rule-2", "alertState": "ALERTING", "detectionFields": [{"key": "hostname", "value": "host2"}]}], "id": "alert-2", "createdTime": "2025-03-02T00:00:00Z"}'
        b']},'
        b'"fieldAggregations": {"fields": [{"fieldName": "detection.rule_name", "baselineAlertCount": 2, "alertCount": 2, "valueCount": 2, '
        b'"allValues": ['
        b'{"value": {"stringValue": "RULE1"}, "baselineAlertCount": 1, "alertCount": 1},'
        b'{"value": {"stringValue": "RULE2"}, "baselineAlertCount": 1, "alertCount": 1}'
        b']}]}}'
    ]
    
    with patch('time.sleep'), patch.object(chronicle_client.session, 'get', return_value=response):
        result = chronicle_client.get_alerts(
            start_time=datetime(2025, 3, 1, tzinfo=timezone.utc),
            end_time=datetime(2025, 3, 3, tzinfo=timezone.utc),
            max_attempts=1  # Only make one request
        )
        
        # Verify that complex nested structures are correctly processed
        assert result.get('complete') is True
        assert result.get('baselineAlertsCount') == 2
        assert result.get('filteredAlertsCount') == 2
        
        # Check alerts list
        alerts = result.get('alerts', {}).get('alerts', [])
        assert len(alerts) == 2
        
        # First alert
        assert alerts[0].get('id') == 'alert-1'
        assert alerts[0].get('detection')[0].get('ruleName') == 'RULE1'
        assert alerts[0].get('detection')[0].get('detectionFields')[0].get('value') == 'host1'
        
        # Second alert
        assert alerts[1].get('id') == 'alert-2'
        assert alerts[1].get('detection')[0].get('ruleName') == 'RULE2'
        assert alerts[1].get('detection')[0].get('detectionFields')[0].get('value') == 'host2'
        
        # Field aggregations
        field_aggs = result.get('fieldAggregations', {}).get('fields', [])
        assert len(field_aggs) == 1
        rule_name_field = field_aggs[0]
        assert rule_name_field.get('fieldName') == 'detection.rule_name'
        assert rule_name_field.get('valueCount') == 2
        assert len(rule_name_field.get('allValues', [])) == 2
        rule_values = [v.get('value', {}).get('stringValue') for v in rule_name_field.get('allValues', [])]
        assert 'RULE1' in rule_values
        assert 'RULE2' in rule_values

def test_fix_json_formatting(chronicle_client):
    """Test JSON formatting fix helper method."""
    # Test trailing commas in arrays
    json_with_array_trailing_comma = '{"items": [1, 2, 3,]}'
    fixed = chronicle_client._fix_json_formatting(json_with_array_trailing_comma)
    assert fixed == '{"items": [1, 2, 3]}'
    
    # Test trailing commas in objects
    json_with_object_trailing_comma = '{"a": 1, "b": 2,}'
    fixed = chronicle_client._fix_json_formatting(json_with_object_trailing_comma)
    assert fixed == '{"a": 1, "b": 2}'
    
    # Test multiple trailing commas
    json_with_multiple_trailing_commas = '{"a": [1, 2,], "b": {"c": 3, "d": 4,},}'
    fixed = chronicle_client._fix_json_formatting(json_with_multiple_trailing_commas)
    assert fixed == '{"a": [1, 2], "b": {"c": 3, "d": 4}}'
    
    # Test no trailing commas
    json_without_trailing_commas = '{"a": [1, 2], "b": {"c": 3, "d": 4}}'
    fixed = chronicle_client._fix_json_formatting(json_without_trailing_commas)
    assert fixed == json_without_trailing_commas 