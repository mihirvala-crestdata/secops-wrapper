# Google SecOps SDK for Python

A Python SDK for interacting with Google Security Operations products, currently supporting Chronicle/SecOps SIEM.
This wraps the API for common use cases, including UDM searches, entity lookups, IoCs, alert management, case management, and detection rule management.

## Installation

```bash
pip install secops
```

## Authentication

The SDK supports two main authentication methods:

### 1. Application Default Credentials (ADC)

The simplest and recommended way to authenticate the SDK. Application Default Credentials provide a consistent authentication method that works across different Google Cloud environments and local development.

There are several ways to use ADC:

#### a. Using `gcloud` CLI (Recommended for Local Development)

```bash
# Login and set up application-default credentials
gcloud auth application-default login
```

Then in your code:
```python
from secops import SecOpsClient

# Initialize with default credentials - no explicit configuration needed
client = SecOpsClient()
```

#### b. Using Environment Variable

Set the environment variable pointing to your service account key:
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
```

Then in your code:
```python
from secops import SecOpsClient

# Initialize with default credentials - will automatically use the credentials file
client = SecOpsClient()
```

#### c. Google Cloud Environment (Automatic)

When running on Google Cloud services (Compute Engine, Cloud Functions, Cloud Run, etc.), ADC works automatically without any configuration:

```python
from secops import SecOpsClient

# Initialize with default credentials - will automatically use the service account 
# assigned to your Google Cloud resource
client = SecOpsClient()
```

ADC will automatically try these authentication methods in order:
1. Environment variable `GOOGLE_APPLICATION_CREDENTIALS`
2. Google Cloud SDK credentials (set by `gcloud auth application-default login`)
3. Google Cloud-provided service account credentials
4. Local service account impersonation credentials

### 2. Service Account Authentication

For more explicit control, you can authenticate using a service account. This can be done in two ways:

#### a. Using a Service Account JSON File

```python
from secops import SecOpsClient

# Initialize with service account JSON file
client = SecOpsClient(service_account_path="/path/to/service-account.json")
```

#### b. Using Service Account Info Dictionary

```python
from secops import SecOpsClient

# Service account details as a dictionary
service_account_info = {
    "type": "service_account",
    "project_id": "your-project-id",
    "private_key_id": "key-id",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "client_email": "service-account@project.iam.gserviceaccount.com",
    "client_id": "client-id",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/..."
}

# Initialize with service account info
client = SecOpsClient(service_account_info=service_account_info)
```

## Using the Chronicle API

### Initializing the Chronicle Client

After creating a SecOpsClient, you need to initialize the Chronicle-specific client:

```python
# Initialize Chronicle client
chronicle = client.chronicle(
    customer_id="your-chronicle-instance-id",  # Your Chronicle instance ID
    project_id="your-project-id",             # Your GCP project ID
    region="us"                               # Chronicle API region
)
```

### Basic UDM Search

Search for network connection events:

```python
from datetime import datetime, timedelta, timezone

# Set time range for queries
end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(hours=24)  # Last 24 hours

# Perform UDM search
results = chronicle.search_udm(
    query="""
    metadata.event_type = "NETWORK_CONNECTION"
    ip != ""
    """,
    start_time=start_time,
    end_time=end_time,
    max_events=5
)

# Example response:
{
    "events": [
        {
            "event": {
                "metadata": {
                    "eventTimestamp": "2024-02-09T10:30:00Z",
                    "eventType": "NETWORK_CONNECTION"
                },
                "target": {
                    "ip": "192.168.1.100",
                    "port": 443
                },
                "principal": {
                    "hostname": "workstation-1"
                }
            }
        }
    ],
    "total_events": 1
}
```

### Statistics Queries

Get statistics about network connections grouped by hostname:

```python
stats = chronicle.get_stats(
    query="""metadata.event_type = "NETWORK_CONNECTION"
match:
    target.hostname
outcome:
    $count = count(metadata.id)
order:
    $count desc""",
    start_time=start_time,
    end_time=end_time,
    max_events=1000,
    max_values=10
)

# Example response:
{
    "columns": ["hostname", "count"],
    "rows": [
        {"hostname": "server-1", "count": 1500},
        {"hostname": "server-2", "count": 1200}
    ],
    "total_rows": 2
}
```

### CSV Export

Export specific fields to CSV format:

```python
csv_data = chronicle.fetch_udm_search_csv(
    query='metadata.event_type = "NETWORK_CONNECTION"',
    start_time=start_time,
    end_time=end_time,
    fields=["timestamp", "user", "hostname", "process name"]
)

# Example response:
"""
metadata.eventTimestamp,principal.hostname,target.ip,target.port
2024-02-09T10:30:00Z,workstation-1,192.168.1.100,443
2024-02-09T10:31:00Z,workstation-2,192.168.1.101,80
"""
```

### Query Validation

Validate a UDM query before execution:

```python
query = 'target.ip != "" and principal.hostname = "test-host"'
validation = chronicle.validate_query(query)

# Example response:
{
    "isValid": true,
    "queryType": "QUERY_TYPE_UDM_QUERY",
    "suggestedFields": [
        "target.ip",
        "principal.hostname"
    ]
}
```

### Entity Summary

Get detailed information about specific entities:

```python
# IP address summary
ip_summary = chronicle.summarize_entity(
    start_time=start_time,
    end_time=end_time,
    value="192.168.1.100"  # Automatically detects IP
)

# Domain summary 
domain_summary = chronicle.summarize_entity(
    start_time=start_time,
    end_time=end_time,
    value="example.com"  # Automatically detects domain
)

# File hash summary
file_summary = chronicle.summarize_entity(
    start_time=start_time,
    end_time=end_time,
    value="e17dd4eef8b4978673791ef4672f4f6a"  # Automatically detects MD5
)

# Example response structure:
{
    "entities": [
        {
            "name": "entities/...",
            "metadata": {
                "entityType": "ASSET",
                "interval": {
                    "startTime": "2024-02-08T10:30:00Z",
                    "endTime": "2024-02-09T10:30:00Z"
                }
            },
            "metric": {
                "firstSeen": "2024-02-08T10:30:00Z",
                "lastSeen": "2024-02-09T10:30:00Z"
            },
            "entity": {
                "asset": {
                    "ip": ["192.168.1.100"]
                }
            }
        }
    ],
    "alertCounts": [
        {
            "rule": "Suspicious Network Connection",
            "count": 5
        }
    ],
    "widgetMetadata": {
        "detections": 5,
        "total": 1000
    }
}
```

### Entity Summary from Query

Look up entities based on a UDM query:

```python
# Search for a specific file hash across multiple UDM paths
md5_hash = "e17dd4eef8b4978673791ef4672f4f6a"
query = f'target.file.md5 = "{md5_hash}" OR principal.file.md5 = "{md5_hash}"'

entity_summaries = chronicle.summarize_entities_from_query(
    query=query,
    start_time=start_time,
    end_time=end_time
)

# Example response:
[
    {
        "entities": [
            {
                "name": "entities/...",
                "metadata": {
                    "entityType": "FILE",
                    "interval": {
                        "startTime": "2024-02-08T10:30:00Z",
                        "endTime": "2024-02-09T10:30:00Z"
                    }
                },
                "metric": {
                    "firstSeen": "2024-02-08T10:30:00Z",
                    "lastSeen": "2024-02-09T10:30:00Z"
                },
                "entity": {
                    "file": {
                        "md5": "e17dd4eef8b4978673791ef4672f4f6a",
                        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "filename": "suspicious.exe"
                    }
                }
            }
        ]
    }
]
```

### List IoCs (Indicators of Compromise)

Retrieve IoC matches against ingested events:

```python
iocs = chronicle.list_iocs(
    start_time=start_time,
    end_time=end_time,
    max_matches=1000,
    add_mandiant_attributes=True,
    prioritized_only=False
)

# Process the results
for ioc in iocs['matches']:
    ioc_type = next(iter(ioc['artifactIndicator'].keys()))
    ioc_value = next(iter(ioc['artifactIndicator'].values()))
    print(f"IoC Type: {ioc_type}, Value: {ioc_value}")
    print(f"Sources: {', '.join(ioc['sources'])}")
```

The IoC response includes:
- The indicator itself (domain, IP, hash, etc.)
- Sources and categories
- Affected assets in your environment
- First and last seen timestamps
- Confidence scores and severity ratings
- Associated threat actors and malware families (with Mandiant attributes)

### Alerts and Case Management

Retrieve alerts and their associated cases:

```python
# Get non-closed alerts
alerts = chronicle.get_alerts(
    start_time=start_time,
    end_time=end_time,
    snapshot_query='feedback_summary.status != "CLOSED"',
    max_alerts=100
)

# Get alerts from the response
alert_list = alerts.get('alerts', {}).get('alerts', [])

# Extract case IDs from alerts
case_ids = {alert.get('caseName') for alert in alert_list if alert.get('caseName')}

# Get case details
if case_ids:
    cases = chronicle.get_cases(list(case_ids))
    
    # Process cases
    for case in cases.cases:
        print(f"Case: {case.display_name}")
        print(f"Priority: {case.priority}")
        print(f"Status: {case.status}")
```

The alerts response includes:
- Progress status and completion status
- Alert counts (baseline and filtered)
- Alert details (rule information, detection details, etc.)
- Case associations

You can filter alerts using the snapshot query parameter with fields like:
- `detection.rule_name`
- `detection.alert_state`
- `feedback_summary.verdict`
- `feedback_summary.priority`
- `feedback_summary.status`

### Case Management Helpers

The `CaseList` class provides helper methods for working with cases:

```python
# Get details for specific cases
cases = chronicle.get_cases(["case-id-1", "case-id-2"])

# Filter cases by priority
high_priority = cases.filter_by_priority("PRIORITY_HIGH")

# Filter cases by status
open_cases = cases.filter_by_status("STATUS_OPEN")

# Look up a specific case
case = cases.get_case("case-id-1")
```

## Rule Management

The SDK provides comprehensive support for managing Chronicle detection rules:

### Creating Rules

Create new detection rules using YARA-L 2.0 syntax:

```python
rule_text = """
rule simple_network_rule {
    meta:
        description = "Example rule to detect network connections"
        author = "SecOps SDK Example"
        severity = "Medium"
        priority = "Medium"
        yara_version = "YL2.0"
        rule_version = "1.0"
    events:
        $e.metadata.event_type = "NETWORK_CONNECTION"
        $e.principal.hostname != ""
    condition:
        $e
}
"""

# Create the rule
rule = chronicle.create_rule(rule_text)
rule_id = rule.get("name", "").split("/")[-1]
print(f"Rule ID: {rule_id}")
```

### Managing Rules

Retrieve, list, update, enable/disable, and delete rules:

```python
# List all rules
rules = chronicle.list_rules()
for rule in rules.get("rules", []):
    rule_id = rule.get("name", "").split("/")[-1]
    enabled = rule.get("deployment", {}).get("enabled", False)
    print(f"Rule ID: {rule_id}, Enabled: {enabled}")

# Get specific rule
rule = chronicle.get_rule(rule_id)
print(f"Rule content: {rule.get('text')}")

# Update rule
updated_rule = chronicle.update_rule(rule_id, updated_rule_text)

# Enable/disable rule
deployment = chronicle.enable_rule(rule_id, enabled=True)  # Enable
deployment = chronicle.enable_rule(rule_id, enabled=False) # Disable

# Delete rule
chronicle.delete_rule(rule_id)
```

### Retrohunts

Run rules against historical data to find past matches:

```python
from datetime import datetime, timedelta, timezone

# Set time range for retrohunt
end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(days=7)  # Search past 7 days

# Create retrohunt
retrohunt = chronicle.create_retrohunt(rule_id, start_time, end_time)
operation_id = retrohunt.get("name", "").split("/")[-1]

# Check retrohunt status
retrohunt_status = chronicle.get_retrohunt(rule_id, operation_id)
is_complete = retrohunt_status.get("metadata", {}).get("done", False)
```

### Detections and Errors

Monitor rule detections and execution errors:

```python
# List detections for a rule
detections = chronicle.list_detections(rule_id)
for detection in detections.get("detections", []):
    detection_id = detection.get("id", "")
    event_time = detection.get("eventTime", "")
    alerting = detection.get("alertState", "") == "ALERTING"
    print(f"Detection: {detection_id}, Time: {event_time}, Alerting: {alerting}")

# List execution errors for a rule
errors = chronicle.list_errors(rule_id)
for error in errors.get("ruleExecutionErrors", []):
    error_message = error.get("error_message", "")
    create_time = error.get("create_time", "")
    print(f"Error: {error_message}, Time: {create_time}")
```

### Rule Alerts

Search for alerts generated by rules:

```python
# Set time range for alert search
end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(days=7)  # Search past 7 days

# Search for rule alerts
alerts_response = chronicle.search_rule_alerts(
    start_time=start_time,
    end_time=end_time,
    page_size=10
)

# The API returns a nested structure where alerts are grouped by rule
# Extract and process all alerts from this structure
all_alerts = []
too_many_alerts = alerts_response.get('tooManyAlerts', False)

# Process the nested response structure - alerts are grouped by rule
for rule_alert in alerts_response.get('ruleAlerts', []):
    # Extract rule metadata
    rule_metadata = rule_alert.get('ruleMetadata', {})
    rule_id = rule_metadata.get('properties', {}).get('ruleId', 'Unknown')
    rule_name = rule_metadata.get('properties', {}).get('name', 'Unknown')
    
    # Get alerts for this rule
    rule_alerts = rule_alert.get('alerts', [])
    
    # Process each alert
    for alert in rule_alerts:
        # Extract important fields
        alert_id = alert.get("id", "")
        detection_time = alert.get("detectionTimestamp", "")
        commit_time = alert.get("commitTimestamp", "")
        alerting_type = alert.get("alertingType", "")
        
        print(f"Alert ID: {alert_id}")
        print(f"Rule ID: {rule_id}")
        print(f"Rule Name: {rule_name}")
        print(f"Detection Time: {detection_time}")
        
        # Extract events from the alert
        if 'resultEvents' in alert:
            for var_name, event_data in alert.get('resultEvents', {}).items():
                if 'eventSamples' in event_data:
                    for sample in event_data.get('eventSamples', []):
                        if 'event' in sample:
                            event = sample['event']
                            # Process event data
                            event_type = event.get('metadata', {}).get('eventType', 'Unknown')
                            print(f"Event Type: {event_type}")
```

If `tooManyAlerts` is True in the response, consider narrowing your search criteria using a smaller time window or more specific filters.

### Rule Sets

Manage curated rule sets:

```python
# Define deployments for rule sets
deployments = [
    {
        "category_id": "category-uuid",
        "rule_set_id": "ruleset-uuid",
        "precision": "broad",
        "enabled": True,
        "alerting": False
    }
]

# Update rule set deployments
chronicle.batch_update_curated_rule_set_deployments(deployments)
```

### Rule Validation

Validate a YARA-L2 rule before creating or updating it:

```python
# Example rule
rule_text = """
rule test_rule {
    meta:
        description = "Test rule for validation"
        author = "Test Author"
        severity = "Low"
        yara_version = "YL2.0"
        rule_version = "1.0"
    events:
        $e.metadata.event_type = "NETWORK_CONNECTION"
    condition:
        $e
}
"""

# Validate the rule
result = chronicle.validate_rule(rule_text)

if result.success:
    print("Rule is valid")
else:
    print(f"Rule is invalid: {result.message}")
    if result.position:
        print(f"Error at line {result.position['startLine']}, column {result.position['startColumn']}")
```

## Error Handling

The SDK defines several custom exceptions:

```python
from secops.exceptions import SecOpsError, AuthenticationError, APIError

try:
    results = chronicle.search_udm(...)
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except APIError as e:
    print(f"API request failed: {e}")
except SecOpsError as e:
    print(f"General error: {e}")
```

## Value Type Detection

The SDK automatically detects these entity types:
- IPv4 addresses
- MD5/SHA1/SHA256 hashes
- Domain names
- Email addresses
- MAC addresses
- Hostnames

Example of automatic detection:

```python
# These will automatically use the correct field paths and value types
ip_summary = chronicle.summarize_entity(value="192.168.1.100")
domain_summary = chronicle.summarize_entity(value="example.com")
hash_summary = chronicle.summarize_entity(value="e17dd4eef8b4978673791ef4672f4f6a")
```

You can also override the automatic detection:

```python
summary = chronicle.summarize_entity(
    value="example.com",
    field_path="custom.field.path",  # Override automatic detection
    value_type="DOMAIN_NAME"         # Explicitly set value type
)
```

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.