from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from guppy_ics.segmentation.models import (
    CommunicationRecommendation,
    CommunicationRelationship,
    FirewallIntent,
)


def build_firewall_intent(
    recommendations: Iterable[CommunicationRecommendation],
    relationships: Iterable[CommunicationRelationship],
) -> List[FirewallIntent]:
    rel_by_id = {rel.id: rel for rel in relationships}
    intents: List[FirewallIntent] = []

    for rec in recommendations:
        rels = [rel_by_id[rel_id] for rel_id in rec.relationship_ids if rel_id in rel_by_id]
        transport = _same_or_blank(rel.transport for rel in rels)
        destination_port = _same_or_blank(rel.destination_port for rel in rels)
        action = _action_for_assessment(rec.assessment)
        intents.append(
            FirewallIntent(
                action=action,
                source_segment=rec.source_segment,
                destination_segment=rec.destination_segment,
                protocol=rec.protocol,
                transport=transport,
                destination_port=destination_port,
                reason=rec.recommendation,
                relationship_ids=rec.relationship_ids,
            )
        )

    return intents


def _action_for_assessment(assessment: str) -> str:
    if assessment == "EXPECTED":
        return "ALLOW"
    if assessment == "REVIEW":
        return "REVIEW"
    return "DENY-CANDIDATE"


def _same_or_blank(values):
    unique = {v for v in values if v not in (None, "")}
    if len(unique) == 1:
        return next(iter(unique))
    return None
