#!/usr/bin/env python3
"""Example usage of the Google SecOps SDK for Chronicle."""

from datetime import datetime, timedelta, timezone
from secops import SecOpsClient
from pprint import pprint
from secops.exceptions import APIError

def main():
    # Initialize the client
    # Note: This assumes you have GOOGLE_APPLICATION_CREDENTIALS set in your environment
    # or credentials are available through Application Default Credentials
    client = SecOpsClient()
    
    # Configure Chronicle client
    chronicle = client.chronicle(
        customer_id="c3c6260c1c9340dcbbb802603bbf9636",  # Your Chronicle instance ID
        project_id="725716774503",    # Your GCP project ID
        region="us"                      # Chronicle API region
    )
    
    # Set time range for queries
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)  # Last 24 hours
#########################################################################    
    print("\n=== Example 1: Basic UDM Search ===")
    try:
        # Search for network connections
        events = chronicle.search_udm(
            query="""metadata.event_type = "NETWORK_CONNECTION"
            ip != ""
            """,
            start_time=start_time,
            end_time=end_time,
            max_events=5  # Limit results for example
        )
        
        print(f"\nFound {events['total_events']} events")
        if events['events']:
            print("\nFirst event details:")
            pprint(events['events'][0])
    except Exception as e:
        print(f"Error performing UDM search: {e}")
#########################################################################
    print("\n=== Example 2: Stats Query ===")
    try:
        # Get statistics about network connections by hostname
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
        print(stats)
        print("\nTop hostnames by event count:")
        for row in stats['rows']:
            print(f"Hostname: {row.get('target.hostname', 'N/A')}, Count: {row.get('count', 0)}")
    except Exception as e:
        print(f"Error performing stats query: {e}")
#########################################################################
    print("\n=== Example 3: CSV Export ===")
    try:
        # Export specific fields to CSV
        csv_data = chronicle.fetch_udm_search_csv(
            query='metadata.event_type = "NETWORK_CONNECTION"',
            start_time=start_time,
            end_time=end_time,
            fields=[
                "metadata.eventTimestamp",
                "principal.hostname",
                "target.ip",
                "target.port"
            ]
        )
        
        print("\nFirst few lines of CSV export:")
        print('\n'.join(csv_data.split('\n')[:50]))
    except Exception as e:
        print(f"Error exporting to CSV: {e}")
#########################################################################
    print("\n=== Example 4: Query Validation ===")
    try:
        # Validate a UDM query
        query = 'target.ip != "" and principal.hostname = "test-host"'
        validation = chronicle.validate_query(query)
        
        print("\nQuery validation results:")
        pprint(validation)
    except Exception as e:
        print(f"Error validating query: {e}")

#########################################################################
    # Examples of automatic type detection
    try:
        # IP address (automatically uses field_path)
        ip_summary = chronicle.summarize_entity(
            start_time=start_time,
            end_time=end_time,
            value="8.8.8.8"  # Automatically detects IP
        )
        
        # Domain (automatically uses value_type)
        domain_summary = chronicle.summarize_entity(
            start_time=start_time,
            end_time=end_time,
            value="google.com"  # Automatically detects domain
        )
        
        # File hash (automatically uses field_path)
        file_summary = chronicle.summarize_entity(
            start_time=start_time,
            end_time=end_time,
            value="e17dd4eef8b4978673791ef4672f4f6a"  # Automatically detects MD5
        )
        
    except APIError as e:
        print(f"Error: {str(e)}")

#########################################################################
    print("\n=== Example 5: Entity Summary via UDM Search ===")
    try:
        # Look up a file hash across multiple UDM paths
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
        
        print("\nFile Entity Summary:")
        for summary in results:
            for entity in summary.entities:
                print(f"Entity Type: {entity.metadata.entity_type}")
                print(f"First Seen: {entity.metric.first_seen}")
                print(f"Last Seen: {entity.metric.last_seen}")
                file_info = entity.entity.get("file", {})
                print(f"MD5: {file_info.get('md5')}")
                
    except APIError as e:
        print(f"Error: {str(e)}")
#########################################################################
    print("\n=== Example 6: File Entity Summary ===")
    try:
        # Get summary for a file using field_path
        file_summary = chronicle.summarize_entity(
            start_time=start_time,
            end_time=end_time,
            field_path="target.file.md5",  # Use field_path for files
            value="e17dd4eef8b4978673791ef4672f4f6a"
        )
        
        print("\nFile Entity Summary (using summarize_entity):")
        for entity in file_summary.entities:
            print(f"Entity Type: {entity.metadata.entity_type}")
            print(f"First Seen: {entity.metric.first_seen}")
            print(f"Last Seen: {entity.metric.last_seen}")
            file_info = entity.entity.get("file", {})
            print(f"MD5: {file_info.get('md5')}")
            
        if file_summary.alert_counts:
            print("\nAlert Counts:")
            for alert in file_summary.alert_counts:
                print(f"Rule: {alert.rule}")
                print(f"Count: {alert.count}")
                
        if file_summary.widget_metadata:
            print("\nWidget Metadata:")
            print(f"Detections: {file_summary.widget_metadata.detections}")
            print(f"Total Scanners: {file_summary.widget_metadata.total}")
                
    except APIError as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
