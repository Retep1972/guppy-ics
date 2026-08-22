from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from guppy_ics.segmentation.classifier import CATEGORY_LABELS, SEGMENT_DESCRIPTIONS
from guppy_ics.segmentation.models import (
    AssetClassification,
    SegmentCandidate,
    SegmentMembership,
    confidence_level,
)


def infer_segments(
    classifications: Dict[str, AssetClassification],
) -> Tuple[List[SegmentCandidate], Dict[str, SegmentMembership]]:
    by_category: Dict[str, List[AssetClassification]] = defaultdict(list)
    for classification in classifications.values():
        by_category[classification.category].append(classification)

    segments: List[SegmentCandidate] = []
    memberships: Dict[str, SegmentMembership] = {}

    for category in sorted(by_category):
        items = by_category[category]
        segment_id = f"segment-{category.replace('_', '-')}"
        avg_confidence = sum(item.confidence for item in items) / max(1, len(items))
        basis = _basis_for_category(category, items)
        segment = SegmentCandidate(
            id=segment_id,
            name=CATEGORY_LABELS.get(category, category.replace("_", " ").title()),
            category=category,
            description=SEGMENT_DESCRIPTIONS.get(category, "Inferred functional group."),
            assets=sorted(item.asset_id for item in items),
            confidence=round(avg_confidence, 2),
            confidence_level=confidence_level(avg_confidence),
            basis=basis,
        )
        segments.append(segment)
        for item in items:
            memberships[item.asset_id] = SegmentMembership(
                asset_id=item.asset_id,
                segment_id=segment_id,
                confidence=item.confidence,
                confidence_level=item.confidence_level,
                basis=basis[:],
            )

    return segments, memberships


def _basis_for_category(category: str, items: Iterable[AssetClassification]) -> List[str]:
    basis = ["asset_identity"]
    if any(any(ev.source == "protocol" for ev in item.evidence) for item in items):
        basis.append("protocol_relationship")
    if category == "external":
        basis.append("public_addressing")
    if category == "unknown":
        basis = ["insufficient_evidence"]
    return basis
