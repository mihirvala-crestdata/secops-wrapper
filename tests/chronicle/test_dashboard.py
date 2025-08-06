#!/usr/bin/env python3
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
"""Tests for the Dashboard module."""

import json
from typing import Any, Dict
from unittest.mock import Mock, patch

import pytest

from secops.chronicle import dashboard
from secops.chronicle.client import ChronicleClient
from secops.chronicle.dashboard import (
    DashboardAccessType,
    DashboardView,
    InputInterval,
)
from secops.exceptions import APIError


@pytest.fixture
def chronicle_client() -> ChronicleClient:
    """Create a mock Chronicle client for testing.

    Returns:
        A mock ChronicleClient instance.
    """
    with patch("secops.auth.SecOpsAuth") as mock_auth:
        mock_session = Mock()
        mock_session.headers = {}
        mock_auth.return_value.session = mock_session
        client = ChronicleClient(
            customer_id="test-customer", project_id="test-project"
        )
        client.base_url = "https://testapi.com"
        client.instance_id = "test-project/locations/test-location"
        return client


@pytest.fixture
def response_mock() -> Mock:
    """Create a mock API response object.

    Returns:
        A mock response object.
    """
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = {"name": "test-dashboard"}
    return mock


class TestDashboardEnums:
    """Test the Dashboard enum classes."""

    def test_dashboard_view_enum(self) -> None:
        """Test DashboardView enum values."""
        assert DashboardView.BASIC == "NATIVE_DASHBOARD_VIEW_BASIC"
        assert DashboardView.FULL == "NATIVE_DASHBOARD_VIEW_FULL"

    def test_dashboard_access_type_enum(self) -> None:
        """Test DashboardAccessType enum values."""
        assert DashboardAccessType.PUBLIC == "DASHBOARD_PUBLIC"
        assert DashboardAccessType.PRIVATE == "DASHBOARD_PRIVATE"


class TestGetDashboard:
    """Test the get_dashboard function."""

    def test_get_dashboard_success(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test get_dashboard function with successful response."""
        chronicle_client.session.get.return_value = response_mock
        dashboard_id = "test-dashboard"

        result = dashboard.get_dashboard(chronicle_client, dashboard_id)

        chronicle_client.session.get.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}"
        )
        params = {"view": "NATIVE_DASHBOARD_VIEW_BASIC"}
        chronicle_client.session.get.assert_called_with(url, params=params)

        assert result == {"name": "test-dashboard"}

    def test_get_dashboard_with_view(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test get_dashboard function with view parameter."""
        chronicle_client.session.get.return_value = response_mock
        dashboard_id = "test-dashboard"

        result = dashboard.get_dashboard(
            chronicle_client, dashboard_id, view=DashboardView.FULL
        )

        chronicle_client.session.get.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}"
        )
        params = {"view": "NATIVE_DASHBOARD_VIEW_FULL"}
        chronicle_client.session.get.assert_called_with(url, params=params)

        assert result == {"name": "test-dashboard"}

    def test_get_dashboard_error(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test get_dashboard function with error response."""
        response_mock.status_code = 404
        response_mock.text = "Dashboard not found"
        chronicle_client.session.get.return_value = response_mock
        dashboard_id = "nonexistent-dashboard"

        with pytest.raises(APIError, match="Failed to get dashboard"):
            dashboard.get_dashboard(chronicle_client, dashboard_id)


class TestUpdateDashboard:
    """Test the update_dashboard function."""

    def test_update_dashboard_display_name(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test update_dashboard with display_name parameter."""
        chronicle_client.session.patch.return_value = response_mock
        dashboard_id = "test-dashboard"
        display_name = "Updated Dashboard"

        result = dashboard.update_dashboard(
            chronicle_client, dashboard_id, display_name=display_name
        )

        chronicle_client.session.patch.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}"
        )
        params = {"updateMask": "display_name"}
        payload = {"displayName": display_name, "definition": {}}
        chronicle_client.session.patch.assert_called_with(
            url, json=payload, params=params
        )

        assert result == {"name": "test-dashboard"}

    def test_update_dashboard_description(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test update_dashboard with description parameter."""
        chronicle_client.session.patch.return_value = response_mock
        dashboard_id = "test-dashboard"
        description = "Updated description"

        result = dashboard.update_dashboard(
            chronicle_client, dashboard_id, description=description
        )

        chronicle_client.session.patch.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}"
        )
        params = {"updateMask": "description"}
        payload = {"description": description, "definition": {}}
        chronicle_client.session.patch.assert_called_with(
            url, json=payload, params=params
        )

        assert result == {"name": "test-dashboard"}

    def test_update_dashboard_filters(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test update_dashboard with filters parameter."""
        chronicle_client.session.patch.return_value = response_mock
        dashboard_id = "test-dashboard"
        filters = [{"field": "event_type", "value": "PROCESS_LAUNCH"}]

        result = dashboard.update_dashboard(
            chronicle_client, dashboard_id, filters=filters
        )

        chronicle_client.session.patch.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}"
        )
        params = {"updateMask": "definition.filters"}
        payload = {"definition": {"filters": filters}}
        chronicle_client.session.patch.assert_called_with(
            url, json=payload, params=params
        )

        assert result == {"name": "test-dashboard"}

    def test_update_dashboard_charts(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test update_dashboard with charts parameter."""
        chronicle_client.session.patch.return_value = response_mock
        dashboard_id = "test-dashboard"
        charts = [{"chart_id": "chart-1", "position": {"row": 0, "col": 0}}]

        result = dashboard.update_dashboard(
            chronicle_client, dashboard_id, charts=charts
        )

        chronicle_client.session.patch.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}"
        )
        params = {"updateMask": "definition.charts"}
        payload = {"definition": {"charts": charts}}
        chronicle_client.session.patch.assert_called_with(
            url, json=payload, params=params
        )

        assert result == {"name": "test-dashboard"}

    def test_update_dashboard_multiple_fields(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test update_dashboard with multiple parameters."""
        chronicle_client.session.patch.return_value = response_mock
        dashboard_id = "test-dashboard"
        display_name = "Updated Dashboard"
        description = "Updated description"

        result = dashboard.update_dashboard(
            chronicle_client,
            dashboard_id,
            display_name=display_name,
            description=description,
        )

        chronicle_client.session.patch.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}"
        )
        params = {"updateMask": "display_name,description"}
        payload = {
            "displayName": display_name,
            "description": description,
            "definition": {},
        }
        chronicle_client.session.patch.assert_called_with(
            url, json=payload, params=params
        )

        assert result == {"name": "test-dashboard"}

    def test_update_dashboard_error(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test update_dashboard function with error response."""
        response_mock.status_code = 400
        response_mock.text = "Bad Request"
        chronicle_client.session.patch.return_value = response_mock
        dashboard_id = "test-dashboard"

        with pytest.raises(APIError, match="Failed to update dashboard"):
            dashboard.update_dashboard(
                chronicle_client, dashboard_id, display_name="Test"
            )


class TestDeleteDashboard:
    """Test the delete_dashboard function."""

    def test_delete_dashboard_success(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test delete_dashboard function with successful response."""
        response_mock.json.return_value = {"status": "success", "code": 200}
        chronicle_client.session.delete.return_value = response_mock
        dashboard_id = "test-dashboard"

        result = dashboard.delete_dashboard(chronicle_client, dashboard_id)

        chronicle_client.session.delete.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}"
        )
        chronicle_client.session.delete.assert_called_with(url)

        assert result == {"status": "success", "code": 200}

    def test_delete_dashboard_with_project_id(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test delete_dashboard with project ID in dashboard_id."""
        response_mock.json.return_value = {"status": "success", "code": 200}
        chronicle_client.session.delete.return_value = response_mock
        dashboard_id = (
            "projects/test-project/locations/test-location"
            "/nativeDashboards/test-dashboard"
        )

        result = dashboard.delete_dashboard(chronicle_client, dashboard_id)

        chronicle_client.session.delete.assert_called_once()
        expected_id = (
            "test-project/locations/test-location/nativeDashboards/"
            "test-dashboard"
        )
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{expected_id}"
        )
        chronicle_client.session.delete.assert_called_with(url)

        assert result == {"status": "success", "code": 200}

    def test_delete_dashboard_error(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test delete_dashboard function with error response."""
        response_mock.status_code = 404
        response_mock.text = "Dashboard not found"
        chronicle_client.session.delete.return_value = response_mock
        dashboard_id = "nonexistent-dashboard"

        with pytest.raises(APIError, match="Failed to delete dashboard"):
            dashboard.delete_dashboard(chronicle_client, dashboard_id)


class TestRemoveChart:
    """Test the remove_chart function."""

    def test_remove_chart_success(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test remove_chart function with successful response."""
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = "test-dashboard"
        chart_id = "test-chart"

        result = dashboard.remove_chart(
            chronicle_client, dashboard_id, chart_id
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}:removeChart"
        )
        payload = {
            "dashboardChart": "test-project/locations/test-location/"
            "dashboardCharts/test-chart"
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert result == {"name": "test-dashboard"}

    def test_remove_chart_with_full_ids(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test remove_chart with full project IDs."""
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = (
            "projects/test-project/locations/test-location/"
            "nativeDashboards/test-dashboard"
        )
        chart_id = (
            "projects/test-project/locations/test-location/"
            "dashboardCharts/test-chart"
        )

        result = dashboard.remove_chart(
            chronicle_client, dashboard_id, chart_id
        )

        chronicle_client.session.post.assert_called_once()
        expected_id = (
            "test-project/locations/test-location/nativeDashboards/"
            "test-dashboard"
        )
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{expected_id}:removeChart"
        )
        payload = {"dashboardChart": chart_id}
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert result == {"name": "test-dashboard"}

    def test_remove_chart_error(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test remove_chart function with error response."""
        response_mock.status_code = 400
        response_mock.text = "Bad Request"
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = "test-dashboard"
        chart_id = "test-chart"

        with pytest.raises(APIError, match="Failed to remove chart"):
            dashboard.remove_chart(chronicle_client, dashboard_id, chart_id)


class TestListDashboards:
    """Test the list_dashboards function."""

    def test_list_dashboards_success(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test list_dashboards function with successful response."""
        response_mock.json.return_value = {
            "nativeDashboards": [
                {"name": "test-dashboard-1"},
                {"name": "test-dashboard-2"},
            ]
        }
        chronicle_client.session.get.return_value = response_mock

        result = dashboard.list_dashboards(chronicle_client)

        chronicle_client.session.get.assert_called_once()
        url = f"{chronicle_client.base_url}/{chronicle_client.instance_id}/nativeDashboards"
        chronicle_client.session.get.assert_called_with(url, params={})

        assert len(result["nativeDashboards"]) == 2
        assert result["nativeDashboards"][0]["name"] == "test-dashboard-1"
        assert result["nativeDashboards"][1]["name"] == "test-dashboard-2"

    def test_list_dashboards_with_pagination(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test list_dashboards function with pagination parameters."""
        # Mock the API response with pagination data
        response_mock.json.return_value = {
            "nativeDashboards": [
                {"name": "test-dashboard-1"},
                {"name": "test-dashboard-2"},
            ],
            "nextPageToken": "next-page-token",
        }
        chronicle_client.session.get.return_value = response_mock

        # Call the function with pagination parameters
        page_size = 10
        page_token = "current-page-token"
        result = dashboard.list_dashboards(
            chronicle_client, page_size=page_size, page_token=page_token
        )

        # Verify API call was made with correct parameters
        chronicle_client.session.get.assert_called_once()
        url = f"{chronicle_client.base_url}/{chronicle_client.instance_id}/nativeDashboards"
        chronicle_client.session.get.assert_called_with(
            url, params={"pageSize": page_size, "pageToken": page_token}
        )

        # Verify the returned data
        assert len(result["nativeDashboards"]) == 2
        assert result["nativeDashboards"][0]["name"] == "test-dashboard-1"
        assert result["nativeDashboards"][1]["name"] == "test-dashboard-2"
        assert result["nextPageToken"] == "next-page-token"

    def test_list_dashboards_error(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test list_dashboards function with error response."""
        response_mock.status_code = 500
        response_mock.text = "Internal Server Error"
        chronicle_client.session.get.return_value = response_mock

        with pytest.raises(APIError, match="Failed to list dashboards"):
            dashboard.list_dashboards(chronicle_client)


class TestCreateDashboard:
    """Test the create_dashboard function."""

    def test_create_dashboard_minimal(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test create_dashboard with minimal required parameters."""
        chronicle_client.session.post.return_value = response_mock
        display_name = "Test Dashboard"
        access_type = dashboard.DashboardAccessType.PRIVATE

        result = dashboard.create_dashboard(
            chronicle_client, display_name=display_name, access_type=access_type
        )

        chronicle_client.session.post.assert_called_once()
        url = f"{chronicle_client.base_url}/{chronicle_client.instance_id}/nativeDashboards"
        payload = {
            "displayName": display_name,
            "access": "DASHBOARD_PRIVATE",
            "type": "CUSTOM",
            "definition": {},
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert result == {"name": "test-dashboard"}

    def test_create_dashboard_full(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test create_dashboard with all parameters."""
        chronicle_client.session.post.return_value = response_mock
        display_name = "Test Dashboard"
        access_type = dashboard.DashboardAccessType.PUBLIC
        description = "Test description"
        filters = [{"field": "event_type", "value": "PROCESS_LAUNCH"}]
        charts = [{"chart_id": "chart-1", "position": {"row": 0, "col": 0}}]

        result = dashboard.create_dashboard(
            chronicle_client,
            display_name=display_name,
            access_type=access_type,
            description=description,
            filters=filters,
            charts=charts,
        )

        chronicle_client.session.post.assert_called_once()
        url = f"{chronicle_client.base_url}/{chronicle_client.instance_id}/nativeDashboards"
        payload = {
            "displayName": display_name,
            "access": "DASHBOARD_PUBLIC",
            "type": "CUSTOM",
            "description": description,
            "definition": {"filters": filters, "charts": charts},
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert result == {"name": "test-dashboard"}

    def test_create_dashboard_error(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test create_dashboard function with error response."""
        response_mock.status_code = 400
        response_mock.text = "Bad Request"
        chronicle_client.session.post.return_value = response_mock
        display_name = "Test Dashboard"
        access_type = dashboard.DashboardAccessType.PRIVATE

        with pytest.raises(APIError, match="Failed to create dashboard"):
            dashboard.create_dashboard(
                chronicle_client,
                display_name=display_name,
                access_type=access_type,
            )


class TestAddChart:
    """Test the add_chart function."""

    @pytest.fixture
    def chart_layout(self) -> Dict[str, Any]:
        """Create a sample chart layout for testing.

        Returns:
            A dictionary with chart layout configuration.
        """
        return {
            "position": {"row": 0, "column": 0},
            "size": {"width": 6, "height": 4},
        }

    def test_add_chart_minimal(
        self,
        chronicle_client: ChronicleClient,
        response_mock: Mock,
        chart_layout: Dict[str, Any],
    ) -> None:
        """Test add_chart with minimal required parameters."""
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = "test-dashboard"
        display_name = "Test Chart"

        result = dashboard.add_chart(
            chronicle_client,
            dashboard_id=dashboard_id,
            display_name=display_name,
            chart_layout=chart_layout,
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}:addChart"
        )
        expected_payload = {
            "dashboardChart": {
                "displayName": "Test Chart",
                "tileType": "TILE_TYPE_VISUALIZATION",
            },
            "chartLayout": {
                "position": {"row": 0, "column": 0},
                "size": {"width": 6, "height": 4},
            },
        }
        chronicle_client.session.post.assert_called_with(
            url, json=expected_payload
        )

        assert result == {"name": "test-dashboard"}

    def test_add_chart_with_query(
        self,
        chronicle_client: ChronicleClient,
        response_mock: Mock,
        chart_layout: Dict[str, Any],
    ) -> None:
        """Test add_chart with query and interval parameters."""
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = "test-dashboard"
        display_name = "Test Chart"
        query = 'udm.metadata.event_type = "PROCESS_LAUNCH"'
        # Using InputInterval as imported from dashboard module

        interval = InputInterval(
            relative_time={"timeUnit": "DAY", "startTimeVal": "1"}
        )

        result = dashboard.add_chart(
            chronicle_client,
            dashboard_id=dashboard_id,
            display_name=display_name,
            chart_layout=chart_layout,
            query=query,
            interval=interval,
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}:addChart"
        )
        payload = {
            "dashboardChart": {
                "displayName": "Test Chart",
                "tileType": "TILE_TYPE_VISUALIZATION",
            },
            "chartLayout": {
                "position": {"row": 0, "column": 0},
                "size": {"width": 6, "height": 4},
            },
            "dashboardQuery": {
                "query": 'udm.metadata.event_type = "PROCESS_LAUNCH"',
                "input": {
                    "relativeTime": {"timeUnit": "DAY", "startTimeVal": "1"}
                },
            },
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert result == {"name": "test-dashboard"}

    def test_add_chart_with_string_json_params(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test add_chart with string JSON parameters."""
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = "test-dashboard"
        display_name = "Test Chart"
        chart_layout_str = (
            '{"position": {"row": 0, "column": 0}, "size": '
            '{"width": 6, "height": 4}}'
        )
        visualization_str = '{"type": "BAR_CHART"}'

        result = dashboard.add_chart(
            chronicle_client,
            dashboard_id=dashboard_id,
            display_name=display_name,
            chart_layout=chart_layout_str,
            visualization=visualization_str,
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}:addChart"
        )
        payload = {
            "dashboardChart": {
                "displayName": "Test Chart",
                "tileType": "TILE_TYPE_VISUALIZATION",
                "visualization": {"type": "BAR_CHART"},
            },
            "chartLayout": {
                "position": {"row": 0, "column": 0},
                "size": {"width": 6, "height": 4},
            },
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert result == {"name": "test-dashboard"}

    def test_add_chart_error(
        self,
        chronicle_client: ChronicleClient,
        response_mock: Mock,
        chart_layout: Dict[str, Any],
    ) -> None:
        """Test add_chart function with error response."""
        response_mock.status_code = 400
        response_mock.text = "Bad Request"
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = "test-dashboard"
        display_name = "Test Chart"

        with pytest.raises(APIError, match="Failed to add chart"):
            dashboard.add_chart(
                chronicle_client,
                dashboard_id=dashboard_id,
                display_name=display_name,
                chart_layout=chart_layout,
            )


class TestExecuteQuery:
    """Test the execute_query function."""

    @pytest.fixture
    def interval(self) -> dashboard.InputInterval:
        """Create a sample interval for testing.

        Returns:
            An InputInterval instance.
        """
        return dashboard.InputInterval(
            relative_time={"timeUnit": "DAY", "startTimeVal": "1"}
        )

    def test_execute_query_success(
        self,
        chronicle_client: ChronicleClient,
        response_mock: Mock,
        interval: dashboard.InputInterval,
    ) -> None:
        """Test execute_query function with successful response."""
        response_mock.json.return_value = {
            "results": [{"value": "test-result"}]
        }
        chronicle_client.session.post.return_value = response_mock
        query = 'udm.metadata.event_type = "PROCESS_LAUNCH"'

        result = dashboard.execute_query(
            chronicle_client, query=query, interval=interval
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            "dashboardQueries:execute"
        )
        payload = {
            "query": {
                "query": 'udm.metadata.event_type = "PROCESS_LAUNCH"',
                "input": interval.to_dict(),
            }
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert "results" in result
        assert result["results"][0]["value"] == "test-result"

    def test_execute_query_with_filters(
        self,
        chronicle_client: ChronicleClient,
        response_mock: Mock,
        interval: dashboard.InputInterval,
    ) -> None:
        """Test execute_query with filters parameter."""
        response_mock.json.return_value = {"results": []}
        chronicle_client.session.post.return_value = response_mock
        query = 'udm.metadata.event_type = "PROCESS_LAUNCH"'
        filters = [{"field": "hostname", "value": "test-host"}]

        result = dashboard.execute_query(
            chronicle_client, query=query, interval=interval, filters=filters
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            "dashboardQueries:execute"
        )
        payload = {
            "query": {"query": query, "input": interval.to_dict()},
            "filters": filters,
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert "results" in result

    def test_execute_query_with_clear_cache(
        self,
        chronicle_client: ChronicleClient,
        response_mock: Mock,
        interval: dashboard.InputInterval,
    ) -> None:
        """Test execute_query with clear_cache parameter."""
        response_mock.json.return_value = {"results": []}
        chronicle_client.session.post.return_value = response_mock
        query = 'udm.metadata.event_type = "PROCESS_LAUNCH"'

        result = dashboard.execute_query(
            chronicle_client, query=query, interval=interval, clear_cache=True
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            "dashboardQueries:execute"
        )
        payload = {
            "query": {"query": query, "input": interval.to_dict()},
            "clearCache": True,
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert "results" in result

    def test_execute_query_with_string_json(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test execute_query with string JSON interval."""
        response_mock.json.return_value = {"results": []}
        chronicle_client.session.post.return_value = response_mock
        query = 'udm.metadata.event_type = "PROCESS_LAUNCH"'
        interval_str = (
            '{"relativeTime": {"timeUnit": "DAY", "startTimeVal": "1"}}'
        )

        result = dashboard.execute_query(
            chronicle_client, query=query, interval=interval_str
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            "dashboardQueries:execute"
        )
        payload = {"query": {"query": query, "input": json.loads(interval_str)}}
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert "results" in result

    def test_execute_query_error(
        self,
        chronicle_client: ChronicleClient,
        response_mock: Mock,
        interval: dashboard.InputInterval,
    ) -> None:
        """Test execute_query function with error response."""
        response_mock.status_code = 400
        response_mock.text = "Invalid Query"
        chronicle_client.session.post.return_value = response_mock
        query = "invalid query syntax"

        with pytest.raises(APIError, match="Failed to execute query"):
            dashboard.execute_query(
                chronicle_client, query=query, interval=interval
            )


class TestDuplicateDashboard:
    """Test the duplicate_dashboard function."""

    def test_duplicate_dashboard_minimal(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test duplicate_dashboard with minimal required parameters."""
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = "test-dashboard"
        display_name = "Duplicated Dashboard"
        access_type = dashboard.DashboardAccessType.PRIVATE

        result = dashboard.duplicate_dashboard(
            chronicle_client,
            dashboard_id=dashboard_id,
            display_name=display_name,
            access_type=access_type,
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}:duplicate"
        )
        payload = {
            "nativeDashboard": {
                "displayName": display_name,
                "access": "DASHBOARD_PRIVATE",
                "type": "CUSTOM",
            }
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert result == {"name": "test-dashboard"}

    def test_duplicate_dashboard_with_description(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test duplicate_dashboard with description parameter."""
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = "test-dashboard"
        display_name = "Duplicated Dashboard"
        access_type = dashboard.DashboardAccessType.PUBLIC
        description = "Duplicated dashboard description"

        result = dashboard.duplicate_dashboard(
            chronicle_client,
            dashboard_id=dashboard_id,
            display_name=display_name,
            access_type=access_type,
            description=description,
        )

        chronicle_client.session.post.assert_called_once()
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{dashboard_id}:duplicate"
        )
        payload = {
            "nativeDashboard": {
                "displayName": display_name,
                "access": "DASHBOARD_PUBLIC",
                "type": "CUSTOM",
                "description": description,
            }
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert result == {"name": "test-dashboard"}

    def test_duplicate_dashboard_with_project_id(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test duplicate_dashboard with project ID in dashboard_id."""
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = (
            "projects/test-project/locations/test-location"
            "/nativeDashboards/test-dashboard"
        )
        display_name = "Duplicated Dashboard"
        access_type = dashboard.DashboardAccessType.PRIVATE

        result = dashboard.duplicate_dashboard(
            chronicle_client,
            dashboard_id=dashboard_id,
            display_name=display_name,
            access_type=access_type,
        )

        chronicle_client.session.post.assert_called_once()
        expected_id = (
            "test-project/locations/test-location/nativeDashboards/"
            "test-dashboard"
        )
        url = (
            f"{chronicle_client.base_url}/{chronicle_client.instance_id}/"
            f"nativeDashboards/{expected_id}:duplicate"
        )
        payload = {
            "nativeDashboard": {
                "displayName": display_name,
                "access": "DASHBOARD_PRIVATE",
                "type": "CUSTOM",
            }
        }
        chronicle_client.session.post.assert_called_with(url, json=payload)

        assert result == {"name": "test-dashboard"}

    def test_duplicate_dashboard_error(
        self, chronicle_client: ChronicleClient, response_mock: Mock
    ) -> None:
        """Test duplicate_dashboard function with error response."""
        response_mock.status_code = 404
        response_mock.text = "Dashboard not found"
        chronicle_client.session.post.return_value = response_mock
        dashboard_id = "nonexistent-dashboard"
        display_name = "Duplicated Dashboard"
        access_type = dashboard.DashboardAccessType.PRIVATE

        with pytest.raises(APIError, match="Failed to duplicate dashboard"):
            dashboard.duplicate_dashboard(
                chronicle_client,
                dashboard_id=dashboard_id,
                display_name=display_name,
                access_type=access_type,
            )
