from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple

from guppy_ics.segmentation.classifier import classify_assets
from guppy_ics.segmentation.firewall import build_firewall_intent
from guppy_ics.segmentation.models import (
    AssessmentEvidence,
    Boundary,
    CommunicationRecommendation,
    CommunicationRelationship,
    SegmentationAssessment,
    confidence_level,
)
from guppy_ics.segmentation.relationships import build_relationships
from guppy_ics.segmentation.rules import assess_relationships, relationship_assessment
from guppy_ics.segmentation.scoring import assessment_confidence, score_posture
from guppy_ics.segmentation.segments import infer_segments


def assess_segmentation(state: Any) -> SegmentationAssessment:
    classifications = classify_assets(state)
    segments, memberships = infer_segments(classifications)
    relationships = build_relationships(state, classifications, memberships)
    findings = assess_relationships(relationships)
    recommendations = build_communication_recommendations(relationships)
    boundaries = build_boundaries(relationships)
    firewall_intent = build_firewall_intent(recommendations, relationships)
    posture = score_posture(findings)
    confidence = assessment_confidence(classifications.values(), len(relationships))

    severity_counts = Counter(f.severity for f in findings)
    summary = {
        "posture": posture,
        "assessment_confidence": confidence,
        "assets": len(classifications),
        "classified_assets": sum(1 for item in classifications.values() if item.category != "unknown"),
        "candidate_segments": len(segments),
        "cross_segment_relationships": sum(1 for rel in relationships if rel.source_segment != rel.destination_segment),
        "findings": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "review": sum(1 for f in findings if f.assessment == "REVIEW"),
        },
    }

    return SegmentationAssessment(
        posture=posture,
        assessment_confidence=confidence,
        summary=summary,
        asset_classifications=list(classifications.values()),
        segments=segments,
        memberships=list(memberships.values()),
        relationships=relationships,
        boundaries=boundaries,
        findings=findings,
        communication_recommendations=recommendations,
        firewall_intent=firewall_intent,
    )


def build_communication_recommendations(
    relationships: List[CommunicationRelationship],
) -> List[CommunicationRecommendation]:
    grouped: Dict[Tuple[str, str, str, str], List[CommunicationRelationship]] = defaultdict(list)
    for rel in relationships:
        if not rel.source_segment or not rel.destination_segment:
            continue
        assessment, recommendation = relationship_assessment(rel)
        key = (rel.source_segment, rel.destination_segment, rel.protocol, assessment)
        grouped[key].append(rel)

    recommendations: List[CommunicationRecommendation] = []
    for (src, dst, protocol, assessment), rels in sorted(grouped.items()):
        _, recommendation = relationship_assessment(rels[0])
        evidence = [
            AssessmentEvidence(
                source="segmentation.summary",
                detail=f"{len(rels)} observed relationship(s) summarized",
                status="inferred",
            )
        ]
        recommendations.append(
            CommunicationRecommendation(
                source_segment=src,
                destination_segment=dst,
                protocol=protocol,
                assessment=assessment,
                recommendation=recommendation,
                relationship_ids=[rel.id for rel in rels],
                evidence=evidence,
            )
        )
    return recommendations


def build_boundaries(relationships: List[CommunicationRelationship]) -> List[Boundary]:
    grouped: Dict[Tuple[str, str], List[CommunicationRelationship]] = defaultdict(list)
    for rel in relationships:
        if rel.source_segment and rel.destination_segment and rel.source_segment != rel.destination_segment:
            grouped[(rel.source_segment, rel.destination_segment)].append(rel)

    boundaries: List[Boundary] = []
    for index, ((src, dst), rels) in enumerate(sorted(grouped.items()), start=1):
        assessments = [relationship_assessment(rel)[0] for rel in rels]
        assessment = _highest_assessment(assessments)
        confidence = sum(rel.confidence for rel in rels) / max(1, len(rels))
        boundaries.append(
            Boundary(
                id=f"boundary-{index:03d}",
                source_segment=src,
                destination_segment=dst,
                protocols=sorted({rel.protocol for rel in rels}),
                relationship_ids=[rel.id for rel in rels],
                assessment=assessment,
                risk=_risk_for_assessment(assessment),
                recommended_control=_control_for_assessment(assessment),
                confidence=round(confidence, 2),
                confidence_level=confidence_level(confidence),
            )
        )
    return boundaries


def _highest_assessment(values: List[str]) -> str:
    order = {"CRITICAL": 4, "RISKY": 3, "REVIEW": 2, "UNKNOWN": 1, "EXPECTED": 0}
    return max(values or ["UNKNOWN"], key=lambda value: order.get(value, 1))


def _risk_for_assessment(assessment: str) -> str:
    return {
        "CRITICAL": "critical",
        "RISKY": "high",
        "REVIEW": "medium",
        "EXPECTED": "low",
    }.get(assessment, "medium")


def _control_for_assessment(assessment: str) -> str:
    if assessment == "EXPECTED":
        return "Permit required traffic through an explicit controlled boundary."
    if assessment == "REVIEW":
        return "Review and document whether this path is required before allowing broadly."
    return "Investigate and restrict; any deny action is a candidate requiring engineering validation."
