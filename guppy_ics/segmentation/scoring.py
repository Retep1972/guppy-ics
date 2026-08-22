from __future__ import annotations

from collections import Counter
from typing import Iterable

from guppy_ics.segmentation.models import AssetClassification, SegmentationFinding


def score_posture(findings: Iterable[SegmentationFinding]) -> str:
    counts = Counter(f.severity for f in findings)
    if counts["critical"]:
        return "poor"
    if counts["high"] >= 2:
        return "weak"
    if counts["high"] or counts["medium"] >= 3:
        return "moderate"
    if sum(counts.values()) == 0:
        return "good"
    return "moderate"


def assessment_confidence(classifications: Iterable[AssetClassification], relationship_count: int) -> str:
    items = list(classifications)
    if not items or relationship_count == 0:
        return "insufficient_data"
    avg = sum(item.confidence for item in items) / len(items)
    if avg >= 0.80:
        return "high"
    if avg >= 0.55:
        return "medium"
    return "low"
