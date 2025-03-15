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
"""Chronicle API specific functionality."""

from secops.chronicle.client import ChronicleClient, _detect_value_type, ValueType
from secops.chronicle.udm_search import fetch_udm_search_csv
from secops.chronicle.validate import validate_query
from secops.chronicle.stats import get_stats
from secops.chronicle.search import search_udm
from secops.chronicle.entity import summarize_entity, summarize_entities_from_query
from secops.chronicle.ioc import list_iocs
from secops.chronicle.case import get_cases
from secops.chronicle.alert import get_alerts
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
    Case,
    SoarPlatformInfo,
    CaseList
)

__all__ = [
    "ChronicleClient",
    "ValueType",
    "fetch_udm_search_csv",
    "validate_query",
    "get_stats",
    "search_udm",
    "summarize_entity",
    "summarize_entities_from_query",
    "list_iocs",
    "get_cases",
    "get_alerts",
    "Entity",
    "EntityMetadata",
    "EntityMetrics",
    "TimeInterval",
    "TimelineBucket",
    "Timeline",
    "WidgetMetadata",
    "EntitySummary",
    "AlertCount",
    "Case",
    "SoarPlatformInfo",
    "CaseList"
] 