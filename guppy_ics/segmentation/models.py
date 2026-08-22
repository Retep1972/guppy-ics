from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


CONFIDENCE_LEVELS = (
    (0.90, "very_high"),
    (0.70, "high"),
    (0.40, "medium"),
    (0.00, "low"),
)


def confidence_level(value: float) -> str:
    for threshold, label in CONFIDENCE_LEVELS:
        if value >= threshold:
            return label
    return "low"


@dataclass
class AssessmentEvidence:
    source: str
    detail: str
    status: str = "observed"


@dataclass
class AssetClassification:
    asset_id: str
    name: str
    identifiers: Dict[str, List[str]]
    role: Optional[str]
    vendor: Optional[str]
    protocols: List[str]
    category: str
    confidence: float
    confidence_level: str
    evidence: List[AssessmentEvidence] = field(default_factory=list)
    status: str = "inferred"


@dataclass
class SegmentMembership:
    asset_id: str
    segment_id: str
    confidence: float
    confidence_level: str
    basis: List[str] = field(default_factory=list)
    status: str = "inferred"


@dataclass
class SegmentCandidate:
    id: str
    name: str
    category: str
    description: str
    assets: List[str] = field(default_factory=list)
    confidence: float = 0.0
    confidence_level: str = "low"
    basis: List[str] = field(default_factory=list)
    status: str = "inferred"


@dataclass
class CommunicationRelationship:
    id: str
    source_asset: str
    destination_asset: str
    source_segment: Optional[str]
    destination_segment: Optional[str]
    source_category: str
    destination_category: str
    protocol: str
    function: Optional[str] = None
    transport: Optional[str] = None
    source_port: Optional[Any] = None
    destination_port: Optional[Any] = None
    packet_count: int = 0
    evidence: List[AssessmentEvidence] = field(default_factory=list)
    confidence: float = 0.75


@dataclass
class Boundary:
    id: str
    source_segment: str
    destination_segment: str
    protocols: List[str]
    relationship_ids: List[str]
    assessment: str
    risk: str
    recommended_control: str
    confidence: float
    confidence_level: str


@dataclass
class SegmentationFinding:
    id: str
    rule_id: str
    title: str
    severity: str
    assessment: str
    source_asset: Optional[str]
    source_segment: Optional[str]
    destination_asset: Optional[str]
    destination_segment: Optional[str]
    protocol: Optional[str]
    transport: Optional[str]
    destination_port: Optional[Any]
    observed: bool
    inferred: bool
    recommendation: str
    confidence: float
    confidence_level: str
    evidence: List[AssessmentEvidence] = field(default_factory=list)
    standards_context: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class CommunicationRecommendation:
    source_segment: str
    destination_segment: str
    protocol: str
    assessment: str
    recommendation: str
    relationship_ids: List[str]
    evidence: List[AssessmentEvidence] = field(default_factory=list)


@dataclass
class FirewallIntent:
    action: str
    source_segment: str
    destination_segment: str
    protocol: str
    transport: Optional[str]
    destination_port: Optional[Any]
    reason: str
    relationship_ids: List[str] = field(default_factory=list)


@dataclass
class SegmentationAssessment:
    posture: str
    assessment_confidence: str
    summary: Dict[str, Any]
    asset_classifications: List[AssetClassification]
    segments: List[SegmentCandidate]
    memberships: List[SegmentMembership]
    relationships: List[CommunicationRelationship]
    boundaries: List[Boundary]
    findings: List[SegmentationFinding]
    communication_recommendations: List[CommunicationRecommendation]
    firewall_intent: List[FirewallIntent]


def to_plain(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return {k: to_plain(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(v) for v in value]
    if isinstance(value, set):
        return sorted(to_plain(v) for v in value)
    return value
