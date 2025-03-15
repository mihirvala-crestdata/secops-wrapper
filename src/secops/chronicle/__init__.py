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

# Rule functionality
from secops.chronicle.rule import (
    create_rule,
    get_rule,
    list_rules,
    update_rule,
    delete_rule,
    enable_rule
)
from secops.chronicle.rule_alert import (
    get_alert,
    update_alert,
    bulk_update_alerts,
    search_rule_alerts
)
from secops.chronicle.rule_detection import (
    list_detections,
    list_errors
)
from secops.chronicle.rule_retrohunt import (
    create_retrohunt,
    get_retrohunt
)
from secops.chronicle.rule_set import (
    batch_update_curated_rule_set_deployments
)

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
    # Client
    "ChronicleClient",
    "ValueType",
    
    # UDM and Search
    "fetch_udm_search_csv",
    "validate_query",
    "get_stats",
    "search_udm",
    
    # Entity
    "summarize_entity",
    "summarize_entities_from_query",
    
    # IoC
    "list_iocs",
    
    # Case
    "get_cases",
    
    # Alert
    "get_alerts",
    
    # Rule management
    "create_rule",
    "get_rule",
    "list_rules",
    "update_rule",
    "delete_rule",
    "enable_rule",
    
    # Rule alert operations
    "get_alert",
    "update_alert",
    "bulk_update_alerts",
    "search_rule_alerts",
    
    # Rule detection operations
    "list_detections",
    "list_errors",
    
    # Rule retrohunt operations
    "create_retrohunt",
    "get_retrohunt",
    
    # Rule set operations
    "batch_update_curated_rule_set_deployments",
    
    # Models
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