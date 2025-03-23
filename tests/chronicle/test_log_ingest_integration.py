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
"""Integration tests for Chronicle log ingestion functionality."""
import json
import pytest
from datetime import datetime, timezone
from secops import SecOpsClient
from secops.chronicle.log_ingest import ingest_log, get_or_create_forwarder
from secops.exceptions import APIError
from ..config import CHRONICLE_CONFIG, SERVICE_ACCOUNT_JSON


@pytest.mark.integration
def test_log_ingest_forwarder():
    """Test forwarder management with real API."""
    client = SecOpsClient(service_account_info=SERVICE_ACCOUNT_JSON)
    chronicle = client.chronicle(**CHRONICLE_CONFIG)
    
    try:
        # Try to get or create the default forwarder
        forwarder = get_or_create_forwarder(
            client=chronicle,
            display_name="Wrapper-SDK-Forwarder"
        )
        
        # Verify forwarder was created or retrieved
        assert forwarder is not None
        assert "name" in forwarder
        assert "displayName" in forwarder
        assert forwarder["displayName"] == "Wrapper-SDK-Forwarder"
        
        print(f"\nForwarder details: {forwarder}")
        print(f"Forwarder ID: {forwarder['name'].split('/')[-1]}")
    
    except APIError as e:
        print(f"\nAPI Error details: {str(e)}")
        # Skip the test rather than fail if permissions are not available
        if "permission" in str(e).lower():
            pytest.skip("Insufficient permissions to manage forwarders")
        raise


@pytest.mark.integration
def test_log_ingest_okta():
    """Test ingesting an OKTA log with real API."""
    client = SecOpsClient(service_account_info=SERVICE_ACCOUNT_JSON)
    chronicle = client.chronicle(**CHRONICLE_CONFIG)
    
    # Get current time for use in log
    current_time = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    # Sample OKTA log with current timestamp
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
        "published": current_time,  # Use current time
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
        # Ingest the OKTA log
        result = ingest_log(
            client=chronicle,
            log_type="OKTA",
            log_message=json.dumps(okta_log)
        )
        
        # Verify response
        assert result is not None
        # The response may be empty in some environments, but the function shouldn't have raised an error
        print(f"\nSuccessfully ingested OKTA log")
        print(f"Response: {result}")
        if "operation" in result:
            print(f"Operation: {result['operation']}")
        
    except APIError as e:
        print(f"\nAPI Error details: {str(e)}")
        # Skip the test rather than fail if permissions are not available
        if "permission" in str(e).lower():
            pytest.skip("Insufficient permissions to ingest logs")
        raise 