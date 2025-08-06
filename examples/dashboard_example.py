#!/usr/bin/env python
#
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
"""Example script demonstrating Chronicle Dashboard functionality."""

import argparse
import json
import time
import uuid
from typing import Optional

from secops.chronicle.client import ChronicleClient


def get_client(
    project_id: str, customer_id: str, region: str
) -> ChronicleClient:
    """Initialize and return the Chronicle client.

    Args:
        project_id: Google Cloud Project ID
        customer_id: Chronicle Customer ID (UUID)
        region: Chronicle region (us or eu)

    Returns:
        Chronicle client instance
    """
    return ChronicleClient(
        project_id=project_id, customer_id=customer_id, region=region
    )


def example_create_dashboard(chronicle: ChronicleClient) -> Optional[str]:
    """Create a new dashboard.

    Args:
        chronicle: ChronicleClient instance

    Returns:
        Created dashboard ID if successful, None otherwise
    """
    print("\n=== Create Dashboard ===")

    display_name = "Test Dashboard - " + f"{uuid.uuid4()}"
    description = "A test dashboard created via API example"
    access_type = "PRIVATE"

    try:
        print(f"\nCreating dashboard: {display_name}")
        new_dashboard = chronicle.create_dashboard(
            display_name=display_name,
            description=description,
            access_type=access_type,
        )
        dashboard_id = new_dashboard["name"].split("/")[-1]
        print(f"Created dashboard with ID: {dashboard_id}")
        print(json.dumps(new_dashboard, indent=2))
        return dashboard_id
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error creating dashboard: {e}")
        return None


def example_get_dashboard(
    chronicle: ChronicleClient, dashboard_id: str
) -> None:
    """Get a specific dashboard by ID.

    Args:
        chronicle: ChronicleClient instance
        dashboard_id: ID of the dashboard to retrieve
    """
    print("\n=== Get Dashboard ===")

    try:
        print(f"\nGetting dashboard with ID: {dashboard_id}")
        dashboard = chronicle.get_dashboard(dashboard_id=dashboard_id)
        print("Dashboard details:")
        print(json.dumps(dashboard, indent=2))
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error getting dashboard: {e}")


def example_list_dashboards(chronicle: ChronicleClient) -> None:
    """List all available dashboards with pagination.

    Args:
        chronicle: ChronicleClient instance
    """
    print("\n=== List Dashboards ===")

    try:
        print("\nListing dashboards (page 1, size 5):")
        page_size = 5
        dashboards = chronicle.list_dashboards(page_size=page_size)

        # Print first page
        dashboard_list = dashboards.get("nativeDashboards", [])
        print(f"Retrieved {len(dashboard_list)} dashboards")
        for i, dashboard in enumerate(dashboard_list, start=1):
            print(
                f"{i}. {dashboard.get('displayName')} "
                f"(ID: {dashboard.get('name').split('/')[-1]})"
            )

        # Check for pagination
        if "nextPageToken" in dashboards:
            page_token = dashboards["nextPageToken"]
            print("\nListing dashboards (page 2, size 5):")
            next_page = chronicle.list_dashboards(
                page_size=page_size, page_token=page_token
            )
            next_list = next_page.get("nativeDashboards", [])
            for i, dashboard in enumerate(
                next_list, start=len(dashboard_list) + 1
            ):
                print(
                    f"{i}. {dashboard.get('displayName')} "
                    f"(ID: {dashboard.get('name').split('/')[-1]})"
                )
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error listing dashboards: {e}")


def example_update_dashboard(
    chronicle: ChronicleClient, dashboard_id: str
) -> None:
    """Update an existing dashboard.

    Args:
        chronicle: ChronicleClient instance
        dashboard_id: ID of the dashboard to update
    """
    print("\n=== Update Dashboard ===")

    try:
        # First get current dashboard to preserve values we don't want to change
        current = chronicle.get_dashboard(dashboard_id=dashboard_id)

        # Update display name and description
        updated_name = f"Updated Dashboard - {uuid.uuid4()}"
        updated_description = "This dashboard was updated via API example"

        print(f"\nUpdating dashboard {dashboard_id} to: {updated_name}")
        updated = chronicle.update_dashboard(
            dashboard_id=dashboard_id,
            display_name=updated_name,
            description=updated_description,
        )

        print("Dashboard updated successfully:")
        print(
            f"Name changed: {current.get('displayName')} -> "
            f"{updated.get('displayName')}"
        )
        print(f"Description updated to: {updated.get('description')}")
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error updating dashboard: {e}")


def example_duplicate_dashboard(
    chronicle: ChronicleClient, dashboard_id: str
) -> Optional[str]:
    """Duplicate an existing dashboard.

    Args:
        chronicle: ChronicleClient instance
        dashboard_id: ID of the dashboard to duplicate

    Returns:
        New dashboard ID if successful, None otherwise
    """
    print("\n=== Duplicate Dashboard ===")

    try:
        duplicate_name = f"Duplicate Dashboard - {uuid.uuid4()}"
        print(f"\nDuplicating dashboard {dashboard_id} to: {duplicate_name}")

        duplicated = chronicle.duplicate_dashboard(
            dashboard_id=dashboard_id,
            display_name=duplicate_name,
            access_type="PRIVATE",
        )

        duplicate_id = duplicated["name"].split("/")[-1]
        print(f"Dashboard duplicated successfully with ID: {duplicate_id}")
        return duplicate_id
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error duplicating dashboard: {e}")
        return None


def example_add_chart(chronicle: ChronicleClient, dashboard_id: str) -> None:
    """Add a chart to an existing dashboard.

    Args:
        chronicle: ChronicleClient instance
        dashboard_id: ID of the dashboard to add chart to
    """
    print("\n=== Add Chart to Dashboard ===")

    try:
        chart_name = f"Example Chart - {uuid.uuid4()}"

        # Sample chart query
        query = """
metadata.event_type = "NETWORK_DNS"
match:
  principal.hostname
outcome:
  $dns_query_count = count(metadata.id)
order:
  principal.hostname asc
"""

        # Chart layout and configuration
        chart_layout = {"startX": 0, "spanX": 12, "startY": 0, "spanY": 8}

        chart_datasource = {"dataSources": ["UDM"]}

        interval = {"relativeTime": {"timeUnit": "DAY", "startTimeVal": "1"}}

        print(f"\nAdding chart '{chart_name}' to dashboard {dashboard_id}")
        result = chronicle.add_chart(
            dashboard_id=dashboard_id,
            display_name=chart_name,
            chart_layout=chart_layout,
            query=query,
            chart_datasource=chart_datasource,
            interval=interval,
        )

        print("Chart added successfully:")
        print(json.dumps(result, indent=2))
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error adding chart to dashboard: {e}")


def example_execute_dashboard_query(chronicle: ChronicleClient) -> None:
    """Execute a dashboard query.

    Args:
        chronicle: ChronicleClient instance
    """
    print("\n=== Execute Dashboard Query ===")

    try:
        # Sample query
        query = """
metadata.event_type = "USER_LOGIN"
match:
  principal.user.userid
outcome:
  $logon_count = count(metadata.id)
order:
  $logon_count desc
limit: 10
"""

        interval = {"relativeTime": {"timeUnit": "DAY", "startTimeVal": "1"}}

        print("\nExecuting dashboard query:")
        print(query)

        result = chronicle.execute_dashboard_query(
            query=query,
            interval=interval,
        )

        print("\nQuery results:")
        if "results" in result and result["results"]:
            # Display the first few results
            for i, item in enumerate(result["results"][:3], start=1):
                print(f"Result {i}:")
                print(json.dumps(item, indent=2))
            print(f"... (total: {len(result['results'])} results)")
        else:
            print("No results returned")
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error executing dashboard query: {e}")


def example_delete_dashboard(
    chronicle: ChronicleClient, dashboard_id: str
) -> None:
    """Delete a dashboard.

    Args:
        chronicle: ChronicleClient instance
        dashboard_id: ID of the dashboard to delete
    """
    print("\n=== Delete Dashboard ===")

    try:
        print(f"\nDeleting dashboard with ID: {dashboard_id}")
        chronicle.delete_dashboard(dashboard_id=dashboard_id)
        print("Dashboard deleted successfully")
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error deleting dashboard: {e}")


# Map of example functions
EXAMPLES = {
    "1": example_create_dashboard,
    "2": example_get_dashboard,
    "3": example_list_dashboards,
    "4": example_update_dashboard,
    "5": example_duplicate_dashboard,
    "6": example_add_chart,
    "7": example_execute_dashboard_query,
    "8": example_delete_dashboard,
}


def main() -> None:
    """Main function to run examples."""
    parser = argparse.ArgumentParser(
        description="Run Chronicle Dashboard API examples"
    )
    parser.add_argument(
        "--project_id", required=True, help="Google Cloud Project ID"
    )
    parser.add_argument(
        "--customer_id", required=True, help="Chronicle Customer ID (UUID)"
    )
    parser.add_argument(
        "--region", default="us", help="Chronicle region (us or eu)"
    )
    parser.add_argument(
        "--example",
        "-e",
        help=(
            "Example number to run (1-8). "
            "If not specified, runs all examples in sequence. "
            "1: Create Dashboard, 2: Get Dashboard, 3: List Dashboards, "
            "4: Update Dashboard, 5: Duplicate Dashboard, 6: Add Chart, "
            "7: Execute Dashboard Query, 8: Delete Dashboard"
        ),
    )

    args = parser.parse_args()

    # Initialize the client
    chronicle = get_client(args.project_id, args.customer_id, args.region)

    # Keep track of created resources for cleanup
    dashboard_ids = []

    try:
        if args.example:
            if args.example not in EXAMPLES:
                print(
                    f"Invalid example number. Available examples: "
                    f"{', '.join(EXAMPLES.keys())}"
                )
                return

            if args.example == "1":  # Create dashboard
                dashboard_id = EXAMPLES[args.example](chronicle)
                if dashboard_id:
                    dashboard_ids.append(dashboard_id)
            elif args.example == "3":  # List dashboards
                EXAMPLES[args.example](chronicle)
            elif args.example == "7":  # Execute query
                EXAMPLES[args.example](chronicle)
            else:
                # First create a dashboard to use for examples
                dashboard_id = example_create_dashboard(chronicle)
                if dashboard_id:
                    dashboard_ids.append(dashboard_id)
                    time.sleep(2)  # Wait for dashboard to be fully created

                    # Run the specific example with the dashboard ID
                    if args.example == "5":  # Duplicate dashboard
                        duplicate_id = EXAMPLES[args.example](
                            chronicle, dashboard_id
                        )
                        if duplicate_id:
                            dashboard_ids.append(duplicate_id)
                    else:
                        EXAMPLES[args.example](chronicle, dashboard_id)
        else:
            # Run all examples in sequence
            print("\n=== Running all Dashboard examples ===")

            # Create a dashboard
            dashboard_id = example_create_dashboard(chronicle)
            if dashboard_id:
                dashboard_ids.append(dashboard_id)
                time.sleep(2)  # Wait for dashboard to be fully created

                # Run examples that need an existing dashboard
                example_get_dashboard(chronicle, dashboard_id)
                example_list_dashboards(chronicle)
                example_update_dashboard(chronicle, dashboard_id)

                # Duplicate the dashboard
                duplicate_id = example_duplicate_dashboard(
                    chronicle, dashboard_id
                )
                if duplicate_id:
                    dashboard_ids.append(duplicate_id)
                    time.sleep(2)  # Wait for duplicate to be fully created

                # Add a chart to the dashboard
                example_add_chart(chronicle, dashboard_id)
                time.sleep(2)  # Wait for chart to be fully created

                # Run query execution example
                example_execute_dashboard_query(chronicle)

    finally:
        # Clean up all created dashboards
        print("\n=== Cleaning up resources ===")
        for dash_id in dashboard_ids:
            try:
                example_delete_dashboard(chronicle, dash_id)
            except Exception as e:  # pylint: disable=broad-exception-caught
                print(f"Error during cleanup of dashboard {dash_id}: {e}")


if __name__ == "__main__":
    main()
