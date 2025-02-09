# Copyright 2024 Google LLC
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
"""Data models for Chronicle API responses."""
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class TimeInterval:
    """Time interval with start and end times."""
    start_time: datetime
    end_time: datetime

@dataclass
class EntityMetadata:
    """Metadata about an entity."""
    entity_type: str
    interval: TimeInterval

@dataclass
class EntityMetrics:
    """Metrics about an entity."""
    first_seen: datetime
    last_seen: datetime

@dataclass
class DomainInfo:
    """Information about a domain entity."""
    name: str
    first_seen_time: datetime
    last_seen_time: datetime

@dataclass
class AssetInfo:
    """Information about an asset entity."""
    ip: List[str]

@dataclass
class Entity:
    """Entity information returned by Chronicle."""
    name: str
    metadata: EntityMetadata
    metric: EntityMetrics
    entity: Dict  # Can contain domain or asset info

@dataclass
class WidgetMetadata:
    """Metadata for UI widgets."""
    uri: str
    detections: int
    total: int

@dataclass
class TimelineBucket:
    """A bucket in the timeline."""
    alert_count: int = 0
    event_count: int = 0

@dataclass
class Timeline:
    """Timeline information."""
    buckets: List[TimelineBucket]
    bucket_size: str

@dataclass
class AlertCount:
    """Alert count for a rule."""
    rule: str
    count: int

@dataclass
class EntitySummary:
    """Complete entity summary response."""
    entities: List[Entity]
    alert_counts: Optional[List[AlertCount]] = None
    timeline: Optional[Timeline] = None
    widget_metadata: Optional[WidgetMetadata] = None
    has_more_alerts: bool = False
    next_page_token: Optional[str] = None 