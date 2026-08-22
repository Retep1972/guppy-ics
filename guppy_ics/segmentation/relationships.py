from __future__ import annotations

from typing import Any, Dict, List

from guppy_ics.core.communications import filter_communications_for_presentation
from guppy_ics.segmentation.models import AssessmentEvidence, CommunicationRelationship


TRANSPORT_PROTOCOLS = {"ip", "ipv4", "ipv6", "tcp", "udp"}


def build_relationships(
    state: Any,
    classifications: Dict[str, Any],
    memberships: Dict[str, Any],
) -> List[CommunicationRelationship]:
    comms = list((getattr(state, "communications", {}) or {}).values())
    comms = filter_communications_for_presentation(comms, transport_protocols=TRANSPORT_PROTOCOLS)
    relationships: List[CommunicationRelationship] = []

    for index, comm in enumerate(comms, start=1):
        src = str(comm.get("src_asset_id") or "")
        dst = str(comm.get("dst_asset_id") or "")
        src_class = classifications.get(src)
        dst_class = classifications.get(dst)
        src_membership = memberships.get(src)
        dst_membership = memberships.get(dst)
        metadata = comm.get("metadata", {}) or {}
        protocol = str(comm.get("protocol") or "unknown").lower()
        function = comm.get("function")
        count = int(comm.get("count") or 0)

        evidence = [
            AssessmentEvidence(
                source="guppy.communication",
                detail=f"{protocol} observed {count} time(s)",
            )
        ]
        if function:
            evidence.append(AssessmentEvidence(source="guppy.protocol_function", detail=str(function)))
        if metadata.get("dst_port"):
            evidence.append(AssessmentEvidence(source="guppy.transport", detail=f"destination port {metadata.get('dst_port')}"))

        relationships.append(
            CommunicationRelationship(
                id=f"rel-{index:04d}",
                source_asset=src,
                destination_asset=dst,
                source_segment=src_membership.segment_id if src_membership else None,
                destination_segment=dst_membership.segment_id if dst_membership else None,
                source_category=src_class.category if src_class else "unknown",
                destination_category=dst_class.category if dst_class else "unknown",
                protocol=protocol,
                function=str(function) if function else None,
                transport=metadata.get("transport"),
                source_port=metadata.get("src_port"),
                destination_port=metadata.get("dst_port"),
                packet_count=count,
                evidence=evidence,
                confidence=0.80 if protocol not in TRANSPORT_PROTOCOLS else 0.60,
            )
        )

    return relationships
