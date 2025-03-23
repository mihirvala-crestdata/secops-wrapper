#!/usr/bin/env python3
"""Example usage of the Google SecOps SDK for Chronicle."""

from datetime import datetime, timedelta, timezone
from secops import SecOpsClient
from pprint import pprint
from secops.exceptions import APIError
import json
import argparse

def get_client(project_id, customer_id, region):
    """Initialize and return the Chronicle client.
    
    Args:
        project_id: Google Cloud Project ID
        customer_id: Chronicle Customer ID (UUID)
        region: Chronicle region (us or eu)
        
    Returns:
        Chronicle client instance
    """
    client = SecOpsClient()
    chronicle = client.chronicle(
        customer_id=customer_id,
        project_id=project_id,
        region=region
    )
    return chronicle

def get_time_range():
    """Get default time range for queries."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)
    return start_time, end_time

def example_udm_search(chronicle):
    """Example 1: Basic UDM Search."""
    print("\n=== Example 1: Basic UDM Search ===")
    start_time, end_time = get_time_range()
    
    try:
        events = chronicle.search_udm(
            query="""metadata.event_type = "NETWORK_CONNECTION"
            ip != ""
            """,
            start_time=start_time,
            end_time=end_time,
            max_events=5
        )
        
        print(f"\nFound {events['total_events']} events")
        if events['events']:
            print("\nFirst event details:")
            pprint(events['events'][0])
    except Exception as e:
        print(f"Error performing UDM search: {e}")

def example_stats_query(chronicle):
    """Example 2: Stats Query."""
    print("\n=== Example 2: Stats Query ===")
    start_time, end_time = get_time_range()
    
    try:
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
        print("\nTop hostnames by event count:")
        for row in stats['rows']:
            print(f"Hostname: {row.get('target.hostname', 'N/A')}, Count: {row.get('count', 0)}")
    except Exception as e:
        print(f"Error performing stats query: {e}")

def example_entity_summary(chronicle):
    """Example 3: Entity Summary."""
    print("\n=== Example 3: Entity Summary ===")
    start_time, end_time = get_time_range()
    
    try:
        file_summary = chronicle.summarize_entity(
            start_time=start_time,
            end_time=end_time,
            field_path="target.file.md5",
            value="e17dd4eef8b4978673791ef4672f4f6a"
        )
        
        print("\nFile Entity Summary:")
        for entity in file_summary.entities:
            print(f"Entity Type: {entity.metadata.entity_type}")
            print(f"First Seen: {entity.metric.first_seen}")
            print(f"Last Seen: {entity.metric.last_seen}")
            
        if file_summary.alert_counts:
            print("\nAlert Counts:")
            for alert in file_summary.alert_counts:
                print(f"Rule: {alert.rule}")
                print(f"Count: {alert.count}")
    except APIError as e:
        print(f"Error: {str(e)}")

def example_csv_export(chronicle):
    """Example 4: CSV Export."""
    print("\n=== Example 4: CSV Export ===")
    start_time, end_time = get_time_range()
    
    try:
        print("\nExporting network connection events to CSV...")
        csv_data = chronicle.fetch_udm_search_csv(
            query='metadata.event_type = "NETWORK_CONNECTION"',
            start_time=start_time,
            end_time=end_time,
            fields=[
                "timestamp",
                "user",
                "hostname",
                "process name"
            ]
        )
        
        # Print the first few lines of the CSV data
        lines = csv_data.strip().split("\n")
        print(f"\nExported {len(lines)-1} events to CSV")
        print("\nCSV Header:")
        print(lines[0])
        
        # Print a sample of the data (up to 5 rows)
        if len(lines) > 1:
            print("\nSample data rows:")
            for i in range(1, min(6, len(lines))):
                print(lines[i])
            
            # Optionally save to a file
            # with open("chronicle_events.csv", "w") as f:
            #     f.write(csv_data)
            # print("\nSaved CSV data to chronicle_events.csv")
    except APIError as e:
        print(f"Error: {str(e)}")

def example_list_iocs(chronicle):
    """Example 5: List IoCs."""
    print("\n=== Example 5: List IoCs ===")
    start_time, end_time = get_time_range()
    
    try:
        iocs = chronicle.list_iocs(
            start_time=start_time,
            end_time=end_time,
            max_matches=10000
        )
        
        print(f"\nFound {len(iocs['matches'])} IoC matches")
        if iocs['matches']:
            print("\nFirst IoC details:")
            first_ioc = iocs['matches'][0]
            print(f"Type: {next(iter(first_ioc['artifactIndicator'].keys()))}")
            print(f"Value: {next(iter(first_ioc['artifactIndicator'].values()))}")
            print(f"Sources: {', '.join(first_ioc['sources'])}")
    except APIError as e:
        print(f"Error: {str(e)}")

def example_alerts_and_cases(chronicle):
    """Example 6: Alerts and Cases."""
    print("\n=== Example 6: Alerts and Cases ===")
    start_time, end_time = get_time_range()
    
    try:
        print("\nQuerying alerts (this may take a few moments)...")
        alerts = chronicle.get_alerts(
            start_time=start_time,
            end_time=end_time,
            snapshot_query="feedback_summary.status != \"CLOSED\"",
            max_alerts=10
        )
        
        alert_list = alerts.get('alerts', {}).get('alerts', [])
        print(f"\nNumber of alerts in response: {len(alert_list)}")
        
        # Debug: Print all alerts with cases
        print("\nDebug - Alerts with cases:")
        for i, alert in enumerate(alert_list):
            case_name = alert.get('caseName')
            if case_name:
                print(f"\nAlert {i+1}:")
                print(f"Case ID: {case_name}")
                print(f"Alert ID: {alert.get('id')}")
                print(f"Rule Name: {alert.get('detection', [{}])[0].get('ruleName')}")
                print(f"Created Time: {alert.get('createdTime')}")
                print(f"Status: {alert.get('feedbackSummary', {}).get('status')}")
        
        case_ids = {alert.get('caseName') for alert in alert_list if alert.get('caseName')}
        
        if case_ids:
            print(f"\nFound {len(case_ids)} unique case IDs:")
            print(list(case_ids))
            
            cases = chronicle.get_cases(list(case_ids))
            print(f"\nRetrieved {len(cases.cases)} cases:")
            for case in cases.cases:
                print(f"\nCase: {case.display_name}")
                print(f"ID: {case.id}")  # Add case ID for comparison
                print(f"Priority: {case.priority}")
                print(f"Stage: {case.stage}")
                print(f"Status: {case.status}")
                
                # Debug: Print all alerts for this case
                case_alerts = [
                    alert for alert in alert_list
                    if alert.get('caseName') == case.id
                ]
                print(f"Total Alerts for Case: {len(case_alerts)}")
                
                high_sev_alerts = [
                    alert for alert in case_alerts
                    if alert.get('feedbackSummary', {}).get('severityDisplay') == 'HIGH'
                ]
                if high_sev_alerts:
                    print(f"High Severity Alerts: {len(high_sev_alerts)}")
        else:
            print("\nNo cases found in alerts")
    except APIError as e:
        print(f"Error: {str(e)}")

def example_validate_query(chronicle):
    """Example 7: Query Validation."""
    print("\n=== Example 7: Query Validation ===")
    
    # Example 1: Valid UDM Query
    try:
        print("\nValidating a correct UDM query:")
        valid_query = 'metadata.event_type = "NETWORK_CONNECTION"'
        
        print(f"Query: {valid_query}")
        result = chronicle.validate_query(valid_query)
        
        # More sophisticated validity check - a query is valid if it has a queryType 
        # and doesn't have error messages or error text
        is_valid = (
            'queryType' in result and 
            not result.get('errorText') and 
            not result.get('errorType')
        )
        
        print(f"Is valid: {is_valid}")
        print(f"Query type: {result.get('queryType', 'Unknown')}")
        
        if is_valid:
            print("✅ Query is valid")
        elif 'errorText' in result:
            print(f"❌ Validation error: {result['errorText']}")
        elif 'validationMessage' in result:
            print(f"❌ Validation error: {result['validationMessage']}")
            
        # Print the full response for debugging
        print(f"Full response: {result}")
    except APIError as e:
        print(f"Error validating query: {str(e)}")
    
    # Example 2: Invalid UDM Query
    try:
        print("\nValidating an incorrect UDM query:")
        invalid_query = 'metadata.event_type === "NETWORK_CONNECTION"'  # Triple equals is invalid
        
        print(f"Query: {invalid_query}")
        result = chronicle.validate_query(invalid_query)
        
        # More sophisticated validity check
        is_valid = (
            'queryType' in result and 
            not result.get('errorText') and 
            not result.get('errorType')
        )
        
        print(f"Is valid: {is_valid}")
        
        if is_valid:
            print("✅ Query is valid")
        elif 'errorText' in result:
            print(f"❌ Validation error: {result['errorText']}")
        elif 'validationMessage' in result:
            print(f"❌ Validation error: {result['validationMessage']}")
            
        # Print the full response for debugging
        print(f"Full response: {result}")
    except APIError as e:
        print(f"Error validating query: {str(e)}")
    
    # Example 3: Valid Stats Query
    try:
        print("\nValidating a correct stats query:")
        valid_stats_query = """metadata.event_type = "NETWORK_CONNECTION"
match:
    principal.hostname
outcome:
    $count = count(metadata.id)
order:
    $count desc"""
        
        print(f"Query: {valid_stats_query}")
        result = chronicle.validate_query(valid_stats_query)
        
        # More sophisticated validity check
        is_valid = (
            'queryType' in result and 
            not result.get('errorText') and 
            not result.get('errorType')
        )
        
        print(f"Is valid: {is_valid}")
        print(f"Query type: {result.get('queryType', 'Unknown')}")
        
        if is_valid:
            print("✅ Query is valid")
        elif 'errorText' in result:
            print(f"❌ Validation error: {result['errorText']}")
        elif 'validationMessage' in result:
            print(f"❌ Validation error: {result['validationMessage']}")
            
        # Print the full response for debugging
        print(f"Full response: {result}")
    except APIError as e:
        print(f"Error validating query: {str(e)}")

def example_entities_from_query(chronicle):
    """Example 8: Entities from Query."""
    print("\n=== Example 8: Entities from Query ===")
    start_time, end_time = get_time_range()
    
    try:
        # Use a specific file hash search that's more likely to find entity data
        print("\nFinding entities related to a specific file hash:")
        
        # MD5 hash to search for
        md5_hash = "e17dd4eef8b4978673791ef4672f4f6a"
        
        # Search for this hash across multiple UDM fields where it might appear
        # This is a more comprehensive search that will find the file regardless of context
        query = (
            f'principal.file.md5 = "{md5_hash}" OR '
            f'principal.process.file.md5 = "{md5_hash}" OR '
            f'target.file.md5 = "{md5_hash}" OR '
            f'target.process.file.md5 = "{md5_hash}" OR '
            f'security_result.about.file.md5 = "{md5_hash}"'
        )
        
        print(f"MD5 Hash: {md5_hash}")
        print(f"Query: {query}")
        print(f"Time range: {start_time.isoformat()} to {end_time.isoformat()}")
        
        print("\nWhat is summarize_entities_from_query?")
        print("This method takes a search query and finds entities mentioned in matching events.")
        print("It then provides summary information about these entities, such as:")
        print("- Entity types (files, IPs, hosts, users, etc.)")
        print("- First and last seen times")
        print("- Event counts")
        print("- Related alerts")
        print("\nThis is useful for threat hunting and investigation to get a quick overview")
        print("of entities related to potentially suspicious behavior.")
        
        print("\nSending API request to summarize entities...")
        entity_summaries = chronicle.summarize_entities_from_query(
            query=query,
            start_time=start_time,
            end_time=end_time
        )
        
        print(f"\nFound {len(entity_summaries)} entity summaries")
        
        if entity_summaries:
            # Show the first few entities
            max_display = min(3, len(entity_summaries))
            print(f"\nShowing details for first {max_display} entities:")
            
            for i, summary in enumerate(entity_summaries[:max_display]):
                print(f"\nEntity {i+1}:")
                
                for entity in summary.entities:
                    print(f"Entity Type: {entity.metadata.entity_type}")
                    
                    # Try to extract and display the hash if this is a file entity
                    if hasattr(entity, 'entity') and hasattr(entity.entity, 'file'):
                        file_data = entity.entity.file
                        if hasattr(file_data, 'md5'):
                            print(f"MD5: {file_data.md5}")
                        if hasattr(file_data, 'sha1'):
                            print(f"SHA1: {file_data.sha1}")
                        if hasattr(file_data, 'sha256'):
                            print(f"SHA256: {file_data.sha256}")
                        if hasattr(file_data, 'filename'):
                            print(f"Filename: {file_data.filename}")
                    
                    print(f"First Seen: {entity.metric.first_seen}")
                    print(f"Last Seen: {entity.metric.last_seen}")
                    
                    # Remove the event_count attribute which doesn't exist
                    # Print available metric attributes instead
                    print("\nAvailable metric attributes:")
                    for attr_name in dir(entity.metric):
                        # Skip private attributes (those starting with underscore)
                        if not attr_name.startswith('_'):
                            attr_value = getattr(entity.metric, attr_name)
                            # Only print if it's not a method or function
                            if not callable(attr_value):
                                print(f"  - {attr_name}: {attr_value}")
                
                # Show alert information if available
                if summary.alert_counts:
                    print("\nAlerts associated with this entity:")
                    for alert in summary.alert_counts:
                        print(f"  - Rule: {alert.rule}")
                        print(f"    Count: {alert.count}")
                        
                # Print full entity structure for debugging
                print("\nDebug - Entity structure:")
                print("This is the full entity object structure to help understand available attributes")
                try:
                    # Attempt to get all attributes of the entity object
                    for entity in summary.entities:
                        for attr_name in dir(entity):
                            if not attr_name.startswith('_'):  # Skip private attrs
                                print(f"{attr_name}")
                except Exception as e:
                    print(f"Error examining entity structure: {e}")
        else:
            print("\nNo entity summaries found. This could be because:")
            print("1. No events match the query criteria in the time range")
            print("2. The specific file hash doesn't exist in your Chronicle data")
            print("3. The API might not be returning entity data for this query")
            print("\nTry a different time range or a different entity (hash, IP, etc.)")
            
            # Attempt a regular search to see if data exists
            print("\nChecking if any events match the file hash...")
            events = chronicle.search_udm(
                query=query,
                start_time=start_time,
                end_time=end_time,
                max_events=5
            )
            print(f"UDM search found {events.get('total_events', 0)} matching events")
            
            # Suggest trying a regular entity lookup instead
            print("\nYou could also try looking up this hash directly using summarize_entity:")
            print("chronicle.summarize_entity(value=\"e17dd4eef8b4978673791ef4672f4f6a\", start_time=start_time, end_time=end_time)")
            
    except APIError as e:
        print(f"Error in entity query: {str(e)}")

def example_nl_search(chronicle):
    """Example 9: Natural Language Search."""
    print("\n=== Example 9: Natural Language Search ===")
    start_time, end_time = get_time_range()
    
    try:
        # First, translate a natural language query to UDM
        print("\nPart 1: Translate natural language to UDM query")
        print("\nTranslating: 'show me network connections'")
        
        udm_query = chronicle.translate_nl_to_udm("show me network connections")
        print(f"\nTranslated UDM query: {udm_query}")
        
        # Now perform a search using natural language directly
        print("\nPart 2: Perform a search using natural language")
        print("\nSearching for: 'show me network connections'")
        
        results = chronicle.nl_search(
            text="show me network connections",
            start_time=start_time,
            end_time=end_time,
            max_events=5
        )
        
        print(f"\nFound {results['total_events']} events")
        if results['events']:
            print("\nFirst event details:")
            pprint(results['events'][0])
            
        # Try a more specific query
        print("\nPart 3: More specific natural language search")
        print("\nSearching for: 'show me inbound connections to port 443'")
        
        specific_results = chronicle.nl_search(
            text="show me inbound connections to port 443",
            start_time=start_time,
            end_time=end_time,
            max_events=5
        )
        
        print(f"\nFound {specific_results['total_events']} events")
        if specific_results['events']:
            print("\nFirst event details:")
            pprint(specific_results['events'][0])
        
    except APIError as e:
        if "no valid query could be generated" in str(e):
            print(f"\nAPI returned an expected error: {str(e)}")
            print("\nTry using a different phrasing or more specific language.")
            print("Examples of good queries:")
            print("- 'show me all network connections'")
            print("- 'find authentication events'")
            print("- 'show me file modification events'")
        else:
            print(f"API Error: {str(e)}")

def example_log_ingestion(chronicle):
    """Example 10: Log Ingestion."""
    print("\n=== Example 10: Log Ingestion ===")
    
    # Create a sample OKTA log to ingest
    current_time = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    okta_log = {
        "actor": {
            "alternateId": "oshamir1@cymbal-investments.org",
            "detail": None,
            "displayName": "Joe Doe",
            "id": "00u4j7xcb5N6zfiRP5d9",
            "type": "User"
        },
        "client": {
            "userAgent": {
                "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
                "os": "Mac OS X",
                "browser": "SAFARI"
            },
            "zone": "null",
            "device": "Computer",
            "id": None,
            "ipAddress": "159.250.183.180",
            "geographicalContext": {
                "city": "Miami",
                "state": "Florida",
                "country": "United States",
                "postalCode": "33131",
                "geolocation": {
                    "lat": 25.7634,
                    "lon": -80.1886
                }
            }
        },
        "authenticationContext": {
            "authenticationProvider": None,
            "credentialProvider": None,
            "credentialType": None,
            "issuer": None,
            "interface": None,
            "authenticationStep": 0,
            "externalSessionId": "102VLe8EG5zT2yawpoqTqalcA"
        },
        "displayMessage": "User login to Okta",
        "eventType": "user.session.start",
        "outcome": {
            "result": "SUCCESS",
            "reason": None
        },
        "published": current_time,
        "securityContext": {
            "asNumber": 11776,
            "asOrg": "atlantic broadband",
            "isp": "atlantic broadband finance llc",
            "domain": "atlanticbb.net",
            "isProxy": False
        },
        "severity": "INFO",
        "debugContext": {
            "debugData": {
                "dtHash": "57e8b514704467a0b0d82a96331c8082a94540c2cab5eb838250fb06d3939f11",
                "behaviors": "{New Geo-Location=NEGATIVE, New Device=POSITIVE, New IP=POSITIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity=NEGATIVE, New City=POSITIVE}",
                "requestId": "Xfxq0rWgTpMflVcjGjapWAtABNA",
                "requestUri": "/api/v1/authn",
                "threatSuspected": "true",
                "url": "/api/v1/authn?"
            }
        },
        "legacyEventType": "core.user_auth.login_success",
        "transaction": {
            "type": "WEB",
            "id": "Xfxq0rWgTpMflVcjGjapWAtABNA",
            "detail": {}
        },
        "uuid": "661c6bda-12f2-11ea-84eb-2b5358b2525a",
        "version": "0",
        "request": {
            "ipChain": [{
                "ip": "159.250.183.180",
                "geographicalContext": {
                    "city": "Miami",
                    "state": "Florida",
                    "country": "United States",
                    "postalCode": "33131",
                    "geolocation": {
                        "lat": 24.7634,
                        "lon": -81.1666
                    }
                },
                "version": "V4",
                "source": None
            }]
        },
        "target": None
    }
    
    try:
        print("\nPart 1: Creating or Finding a Forwarder")
        forwarder = chronicle.get_or_create_forwarder(display_name="Wrapper-SDK-Forwarder")
        print(f"Using forwarder: {forwarder.get('displayName', 'Unknown')}")
        
        print("\nPart 2: Ingesting OKTA Log")
        print("Ingesting OKTA log with timestamp:", current_time)
        
        result = chronicle.ingest_log(
            log_type="OKTA",
            log_message=json.dumps(okta_log)
        )
        
        print("\nLog ingestion successful!")
        print(f"Operation ID: {result.get('operation', 'Unknown')}")
        
        print("\nPart 3: Listing Available Log Types")
        # Get the first 5 log types for display
        log_types = chronicle.get_all_log_types()[:5]
        print(f"\nFound {len(chronicle.get_all_log_types())} log types. First 5 examples:")
        
        for lt in log_types:
            print(f"- {lt.id}: {lt.description}")
            
        print("\nTip: You can search for specific log types:")
        print('search_result = chronicle.search_log_types("firewall")')
        
    except Exception as e:
        print(f"\nError during log ingestion: {e}")

# Map of example functions
EXAMPLES = {
    '1': example_udm_search,
    '2': example_stats_query,
    '3': example_entity_summary,
    '4': example_csv_export,
    '5': example_list_iocs,
    '6': example_alerts_and_cases,
    '7': example_validate_query,
    '8': example_entities_from_query,
    '9': example_nl_search,
    '10': example_log_ingestion,
}

def main():
    """Main function to run examples."""
    parser = argparse.ArgumentParser(description='Run Chronicle API examples')
    parser.add_argument('--project_id', required=True, help='Google Cloud Project ID')
    parser.add_argument('--customer_id', required=True, help='Chronicle Customer ID (UUID)')
    parser.add_argument('--region', default='us', help='Chronicle region (us or eu)')
    parser.add_argument('--example', '-e', 
                      help='Example number to run (1-10). If not specified, runs all examples.')
    
    args = parser.parse_args()
    
    # Initialize the client
    chronicle = get_client(args.project_id, args.customer_id, args.region)
    
    if args.example:
        if args.example not in EXAMPLES:
            print(f"Invalid example number. Available examples: {', '.join(EXAMPLES.keys())}")
            return
        EXAMPLES[args.example](chronicle)
    else:
        # Run all examples in order
        for example_num in sorted(EXAMPLES.keys()):
            EXAMPLES[example_num](chronicle)

if __name__ == "__main__":
    main()
