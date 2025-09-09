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
"""Unit tests for RetryConfig dataclass."""

import http.client
from http import HTTPStatus, HTTPMethod

from secops.auth import RetryConfig


def test_retry_config_default_values():
    """Test RetryConfig initializes with correct default values."""
    config = RetryConfig()

    assert config.total == 5
    assert HTTPStatus.TOO_MANY_REQUESTS.value in config.retry_status_codes
    assert HTTPStatus.INTERNAL_SERVER_ERROR.value in config.retry_status_codes
    assert HTTPStatus.BAD_GATEWAY.value in config.retry_status_codes
    assert HTTPStatus.SERVICE_UNAVAILABLE.value in config.retry_status_codes
    assert HTTPStatus.GATEWAY_TIMEOUT.value in config.retry_status_codes
    assert HTTPMethod.GET in config.allowed_methods
    assert HTTPMethod.PUT in config.allowed_methods
    assert HTTPMethod.DELETE in config.allowed_methods
    assert HTTPMethod.POST in config.allowed_methods
    assert HTTPMethod.PATCH in config.allowed_methods
    assert config.backoff_factor == 0.3


def test_retry_config_custom_values():
    """Test RetryConfig accepts custom values."""
    custom_config = RetryConfig(
        total=5,
        retry_status_codes=[429, 500],
        allowed_methods=["GET", "POST"],
        backoff_factor=0.5,
    )

    assert custom_config.total == 5
    assert len(custom_config.retry_status_codes) == 2
    assert 429 in custom_config.retry_status_codes
    assert 500 in custom_config.retry_status_codes
    assert len(custom_config.allowed_methods) == 2
    assert "GET" in custom_config.allowed_methods
    assert "POST" in custom_config.allowed_methods
    assert custom_config.backoff_factor == 0.5


def test_retry_config_to_dict():
    """Test RetryConfig.to_dict() returns correct dictionary."""
    config = RetryConfig(total=4, backoff_factor=0.7)
    config_dict = config.to_dict()

    assert isinstance(config_dict, dict)
    assert config_dict["total"] == 4
    assert config_dict["backoff_factor"] == 0.7
    assert "retry_status_codes" in config_dict
    assert "allowed_methods" in config_dict
