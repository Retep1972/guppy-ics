from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from guppy_ics.segmentation.models import (
    AssessmentEvidence,
    CommunicationRelationship,
    SegmentationFinding,
    confidence_level,
)


@dataclass(frozen=True)
class SegmentationRule:
    rule_id: str
    title: str
    description: str
    source_category: Optional[str]
    destination_category: Optional[str]
    protocols: Optional[frozenset[str]]
    assessment: str
    severity: str
    rationale: str
    recommendation: str
    standards_context: Dict[str, List[str]] = field(default_factory=dict)

    def matches(self, rel: CommunicationRelationship) -> bool:
        if self.source_category and self.source_category != rel.source_category:
            return False
        if self.destination_category and self.destination_category != rel.destination_category:
            return False
        if self.protocols and rel.protocol not in self.protocols:
            return False
        return True


DANGEROUS_CONTROL_PROTOCOLS = frozenset({"s7comm", "modbus", "profinet", "dnp3", "iec104", "opcua"})
MANAGEMENT_PROTOCOLS = frozenset({"snmp", "ssh", "telnet", "rdp", "http", "https"})


RULES: List[SegmentationRule] = [
    SegmentationRule(
        rule_id="SEG-CROSS-001",
        title="Enterprise asset directly communicates with process-control asset",
        description="Direct enterprise-to-controller communication crosses a high-trust OT boundary.",
        source_category="enterprise_it",
        destination_category="process_control",
        protocols=None,
        assessment="RISKY",
        severity="high",
        rationale="Enterprise IT assets should normally reach controllers through controlled OT pathways.",
        recommendation="Restrict controller access to explicitly authorized OT engineering or operations systems.",
        standards_context={"iec_62443": ["zone/conduit architecture", "restricted data flow"]},
    ),
    SegmentationRule(
        rule_id="SEG-CROSS-002",
        title="External endpoint communicates with process-control asset",
        description="Public or external endpoint communication to a controller was observed.",
        source_category="external",
        destination_category="process_control",
        protocols=None,
        assessment="CRITICAL",
        severity="critical",
        rationale="Direct external paths to control assets can create high-impact exposure.",
        recommendation="Review whether an enforcing boundary, proxy, or jump path is required before permitting this traffic.",
        standards_context={"iec_62443": ["restricted data flow", "defence in depth"]},
    ),
    SegmentationRule(
        rule_id="SEG-CROSS-003",
        title="Process-control asset communicates with external endpoint",
        description="Controller or field-control asset initiated traffic to an external endpoint.",
        source_category="process_control",
        destination_category="external",
        protocols=None,
        assessment="RISKY",
        severity="high",
        rationale="Outbound Internet paths from process-control assets should be tightly understood and controlled.",
        recommendation="Validate the business requirement and prefer brokered, logged, restricted egress.",
        standards_context={"iec_62443": ["restricted data flow"]},
    ),
    SegmentationRule(
        rule_id="SEG-CROSS-004",
        title="Video surveillance asset communicates with process-control asset",
        description="Camera, NVR, or video system traffic crossed into process-control assets.",
        source_category="video_surveillance",
        destination_category="process_control",
        protocols=None,
        assessment="RISKY",
        severity="high",
        rationale="Video systems normally have no operational need to use controller protocols or reach PLCs directly.",
        recommendation="Investigate the design requirement and isolate video surveillance from process-control networks where practical.",
        standards_context={"iec_62443": ["zone/conduit architecture"]},
    ),
    SegmentationRule(
        rule_id="SEG-CROSS-005",
        title="Operational audio asset communicates with process-control asset",
        description="SIP/RTP/audio-related asset traffic crossed into process-control assets.",
        source_category="operational_audio",
        destination_category="process_control",
        protocols=None,
        assessment="REVIEW",
        severity="medium",
        rationale="Audio and PA systems should usually remain in their own operational segment.",
        recommendation="Review whether this traffic is required and restrict it to documented paths.",
        standards_context={"iec_62443": ["zone/conduit architecture"]},
    ),
    SegmentationRule(
        rule_id="SEG-CROSS-006",
        title="Engineering asset uses control protocol with process-control asset",
        description="Engineering-to-controller communication was observed.",
        source_category="engineering",
        destination_category="process_control",
        protocols=DANGEROUS_CONTROL_PROTOCOLS,
        assessment="EXPECTED",
        severity="info",
        rationale="Engineering tools commonly communicate with controllers using industrial protocols.",
        recommendation="Permit only from authorized engineering assets and log control traffic where feasible.",
        standards_context={"iec_62443": ["controlled communication paths"]},
    ),
    SegmentationRule(
        rule_id="SEG-CROSS-007",
        title="Operations asset communicates with process-control asset",
        description="HMI or SCADA communication with controller assets was observed.",
        source_category="operations",
        destination_category="process_control",
        protocols=None,
        assessment="EXPECTED",
        severity="info",
        rationale="Operations systems commonly poll or supervise controllers.",
        recommendation="Permit restricted operations-to-control communication required by the process.",
        standards_context={"iec_62443": ["controlled communication paths"]},
    ),
    SegmentationRule(
        rule_id="SEG-CROSS-008",
        title="Unknown asset crosses a functional trust boundary",
        description="An insufficiently classified asset communicates across inferred functional groups.",
        source_category="unknown",
        destination_category=None,
        protocols=None,
        assessment="REVIEW",
        severity="medium",
        rationale="Unknown communication should be reviewed, not automatically denied.",
        recommendation="Identify the asset and validate whether this communication is required.",
        standards_context={"iec_62443": ["least privilege"]},
    ),
    SegmentationRule(
        rule_id="SEG-CROSS-009",
        title="Asset communicates with unknown destination across a functional trust boundary",
        description="A known asset communicates with an insufficiently classified destination.",
        source_category=None,
        destination_category="unknown",
        protocols=None,
        assessment="REVIEW",
        severity="medium",
        rationale="Unknown communication should be reviewed, not automatically denied.",
        recommendation="Identify the destination and validate whether this communication is required.",
        standards_context={"iec_62443": ["least privilege"]},
    ),
]


def assess_relationships(relationships: List[CommunicationRelationship]) -> List[SegmentationFinding]:
    findings: List[SegmentationFinding] = []
    for rel in relationships:
        if rel.source_segment == rel.destination_segment:
            continue
        rule = _best_rule(rel)
        if not rule:
            rule = _default_cross_boundary_rule(rel)
        if rule.assessment == "EXPECTED":
            continue
        confidence = min(0.95, max(0.45, rel.confidence))
        findings.append(
            SegmentationFinding(
                id=f"SEG-{len(findings) + 1:03d}",
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                assessment=rule.assessment,
                source_asset=rel.source_asset,
                source_segment=rel.source_segment,
                destination_asset=rel.destination_asset,
                destination_segment=rel.destination_segment,
                protocol=rel.protocol,
                transport=rel.transport,
                destination_port=rel.destination_port,
                observed=True,
                inferred=True,
                recommendation=rule.recommendation,
                confidence=round(confidence, 2),
                confidence_level=confidence_level(confidence),
                evidence=rel.evidence
                + [AssessmentEvidence(source="segmentation.rule", detail=rule.rationale, status="inferred")],
                standards_context=rule.standards_context,
            )
        )

    findings.extend(_pivot_findings(relationships, len(findings)))
    return findings


def relationship_assessment(rel: CommunicationRelationship) -> tuple[str, str]:
    if rel.source_segment == rel.destination_segment:
        return "EXPECTED", "Internal segment communication observed."
    rule = _best_rule(rel) or _default_cross_boundary_rule(rel)
    return rule.assessment, rule.recommendation


def _best_rule(rel: CommunicationRelationship) -> Optional[SegmentationRule]:
    matches = [rule for rule in RULES if rule.matches(rel)]
    if not matches:
        return None
    matches.sort(key=lambda rule: (rule.protocols is None, rule.severity != "critical"))
    return matches[0]


def _default_cross_boundary_rule(rel: CommunicationRelationship) -> SegmentationRule:
    if rel.protocol in MANAGEMENT_PROTOCOLS:
        severity = "medium"
        title = "Management or service protocol crosses a functional trust boundary"
        rationale = "Management and service protocols across functional groups should be explicitly justified."
    else:
        severity = "low"
        title = "Observed communication crosses a functional trust boundary"
        rationale = "Traffic was observed directly between inferred functional groups."
    return SegmentationRule(
        rule_id="SEG-CROSS-DEFAULT",
        title=title,
        description=title,
        source_category=None,
        destination_category=None,
        protocols=None,
        assessment="REVIEW",
        severity=severity,
        rationale=rationale,
        recommendation="Review whether this communication path is required and enforce it at a segmentation boundary if approved.",
        standards_context={"iec_62443": ["zone/conduit architecture", "least privilege"]},
    )


def _pivot_findings(
    relationships: List[CommunicationRelationship],
    starting_count: int,
) -> List[SegmentationFinding]:
    reached: Dict[str, set[str]] = {}
    rels_by_asset: Dict[str, List[CommunicationRelationship]] = {}
    for rel in relationships:
        if rel.source_category != rel.destination_category:
            reached.setdefault(rel.source_asset, set()).add(rel.destination_category)
            rels_by_asset.setdefault(rel.source_asset, []).append(rel)

    findings: List[SegmentationFinding] = []
    for asset_id, categories in sorted(reached.items(), key=lambda item: (-len(item[1]), item[0])):
        if len(categories) < 4:
            continue
        evidence = [
            AssessmentEvidence(
                source="segmentation.graph",
                detail=f"asset reaches {len(categories)} functional categories: {', '.join(sorted(categories))}",
                status="inferred",
            )
        ]
        first_rel = rels_by_asset[asset_id][0]
        findings.append(
            SegmentationFinding(
                id=f"SEG-{starting_count + len(findings) + 1:03d}",
                rule_id="SEG-GRAPH-001",
                title="Asset communicates with many functional groups",
                severity="medium",
                assessment="REVIEW",
                source_asset=asset_id,
                source_segment=first_rel.source_segment,
                destination_asset=None,
                destination_segment=None,
                protocol=None,
                transport=None,
                destination_port=None,
                observed=True,
                inferred=True,
                recommendation="Review this asset as a potential high-impact pivot and verify that each communication path is required.",
                confidence=0.70,
                confidence_level="high",
                evidence=evidence,
                standards_context={"iec_62443": ["least privilege", "restricted data flow"]},
            )
        )
    return findings
