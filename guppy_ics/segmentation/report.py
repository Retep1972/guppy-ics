from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any, Dict

from guppy_ics.segmentation.models import SegmentationAssessment, to_plain


def write_segmentation_outputs(assessment: SegmentationAssessment, out_dir: str | Path) -> Dict[str, Path]:
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)

    outputs = {
        "segments": target / "segments.json",
        "asset_membership": target / "asset_membership.json",
        "communication_matrix_json": target / "communication_matrix.json",
        "communication_matrix_csv": target / "communication_matrix.csv",
        "findings": target / "findings.json",
        "firewall_intent_json": target / "firewall_intent.json",
        "firewall_intent_csv": target / "firewall_intent.csv",
        "segmentation_summary": target / "segmentation_summary.json",
        "segmentation_report": target / "segmentation_report.html",
    }

    _write_json(outputs["segments"], assessment.segments)
    _write_json(outputs["asset_membership"], assessment.memberships)
    _write_json(outputs["communication_matrix_json"], assessment.communication_recommendations)
    _write_json(outputs["findings"], assessment.findings)
    _write_json(outputs["firewall_intent_json"], assessment.firewall_intent)
    _write_json(outputs["segmentation_summary"], assessment.summary)
    _write_matrix_csv(outputs["communication_matrix_csv"], assessment)
    _write_firewall_csv(outputs["firewall_intent_csv"], assessment)
    outputs["segmentation_report"].write_text(render_html_report(assessment), encoding="utf-8")
    return outputs


def render_text_summary(assessment: SegmentationAssessment) -> str:
    lines = [
        "SEGMENTATION ASSESSMENT",
        "",
        f"Assets discovered: {assessment.summary['assets']}",
        f"Assets classified: {assessment.summary['classified_assets']}",
        f"Candidate security segments: {assessment.summary['candidate_segments']}",
        f"Cross-segment relationships: {assessment.summary['cross_segment_relationships']}",
        "",
        f"Segmentation posture: {assessment.posture.upper()}",
        f"Assessment confidence: {assessment.assessment_confidence.upper()}",
        "",
        "CANDIDATE SEGMENTS",
    ]
    for segment in assessment.segments:
        lines.append(f"{segment.name}: {len(segment.assets)} asset(s), confidence {segment.confidence_level}")

    lines.extend(["", "PRIORITY FINDINGS"])
    priority = [f for f in assessment.findings if f.severity in {"critical", "high", "medium"}][:10]
    if not priority:
        lines.append("(no critical/high/medium findings)")
    for finding in priority:
        lines.append(f"{finding.severity.upper()}: {finding.title} [{finding.assessment}]")
        lines.append(f"  Recommendation: {finding.recommendation}")

    lines.extend(["", "OUTPUTS"])
    lines.append("Open segmentation_report.html for the full offline report.")
    return "\n".join(lines) + "\n"


def render_html_report(assessment: SegmentationAssessment) -> str:
    assets_by_id = {asset.asset_id: asset for asset in assessment.asset_classifications}
    segment_name_by_id = {segment.id: segment.name for segment in assessment.segments}

    overview_cards = []
    for segment in assessment.segments:
        asset_items = []
        for asset_id in segment.assets:
            asset = assets_by_id.get(asset_id)
            if not asset:
                continue
            asset_items.append(
                "<li>"
                f"<span class=\"asset-name\">{_h(asset.name)}</span>"
                f"<span class=\"asset-meta\">{_h(_identifier_summary(asset.identifiers))}</span>"
                "</li>"
            )
        asset_list_html = "".join(asset_items) if asset_items else '<li><span class="asset-meta">No assets</span></li>'
        overview_cards.append(
            "<article class=\"segment-card\">"
            f"<h3>{_h(segment.name)}</h3>"
            f"<div class=\"segment-meta\">{len(segment.assets)} asset(s) | {segment.confidence_level} confidence</div>"
            f"<ul>{asset_list_html}</ul>"
            "</article>"
        )

    path_rows = []
    for boundary in assessment.boundaries:
        path_rows.append(
            "<tr>"
            f"<td>{_h(segment_name_by_id.get(boundary.source_segment, boundary.source_segment))}</td>"
            f"<td>{_h(segment_name_by_id.get(boundary.destination_segment, boundary.destination_segment))}</td>"
            f"<td>{_h(', '.join(boundary.protocols))}</td>"
            f"<td>{_h(boundary.assessment)}</td>"
            f"<td>{_h(boundary.risk)}</td>"
            "</tr>"
        )

    findings_rows = []
    for finding in assessment.findings:
        evidence = "; ".join(ev.detail for ev in finding.evidence)
        findings_rows.append(
            "<tr>"
            f"<td>{_h(finding.severity.upper())}</td>"
            f"<td>{_h(finding.title)}</td>"
            f"<td>{_h(_asset_display(assets_by_id, finding.source_asset))}</td>"
            f"<td>{_h(_asset_display(assets_by_id, finding.destination_asset))}</td>"
            f"<td>{_h(finding.assessment)}</td>"
            f"<td>{_h(finding.protocol or '')}</td>"
            f"<td>{_h(finding.recommendation)}</td>"
            f"<td>{_h(evidence)}</td>"
            "</tr>"
        )

    segment_rows = []
    for segment in assessment.segments:
        asset_names = ", ".join(
            assets_by_id[asset_id].name
            for asset_id in segment.assets
            if asset_id in assets_by_id
        )
        segment_rows.append(
            "<tr>"
            f"<td>{_h(segment.name)}</td>"
            f"<td>{_h(segment.category)}</td>"
            f"<td>{len(segment.assets)}</td>"
            f"<td>{_h(asset_names)}</td>"
            f"<td>{_h(segment.confidence_level)}</td>"
            f"<td>{_h(', '.join(segment.basis))}</td>"
            "</tr>"
        )

    asset_rows = []
    for asset in sorted(assessment.asset_classifications, key=lambda item: (item.category, item.name)):
        evidence = "; ".join(ev.detail for ev in asset.evidence)
        asset_rows.append(
            "<tr>"
            f"<td>{_h(asset.name)}</td>"
            f"<td>{_h(_identifier_summary(asset.identifiers))}</td>"
            f"<td>{_h(asset.category)}</td>"
            f"<td>{_h(asset.role or '')}</td>"
            f"<td>{_h(asset.vendor or '')}</td>"
            f"<td>{_h(', '.join(asset.protocols))}</td>"
            f"<td>{_h(asset.confidence_level)}</td>"
            f"<td>{_h(evidence)}</td>"
            "</tr>"
        )

    matrix_rows = []
    for rec in assessment.communication_recommendations:
        matrix_rows.append(
            "<tr>"
            f"<td>{_h(segment_name_by_id.get(rec.source_segment, rec.source_segment))}</td>"
            f"<td>{_h(segment_name_by_id.get(rec.destination_segment, rec.destination_segment))}</td>"
            f"<td>{_h(rec.protocol)}</td>"
            f"<td>{_h(rec.assessment)}</td>"
            f"<td>{_h(rec.recommendation)}</td>"
            "</tr>"
        )

    firewall_rows = []
    for intent in assessment.firewall_intent:
        firewall_rows.append(
            "<tr>"
            f"<td>{_h(intent.action)}</td>"
            f"<td>{_h(segment_name_by_id.get(intent.source_segment, intent.source_segment))}</td>"
            f"<td>{_h(segment_name_by_id.get(intent.destination_segment, intent.destination_segment))}</td>"
            f"<td>{_h(intent.protocol)}</td>"
            f"<td>{_h(intent.transport or '')}</td>"
            f"<td>{_h(intent.destination_port or '')}</td>"
            f"<td>{_h(intent.reason)}</td>"
            "</tr>"
        )

    summary = assessment.summary
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Guppy ICS Segmentation Assessment</title>
  <style>
    body {{ background:#07110b; color:#28ff72; font-family: Consolas, monospace; margin: 24px; line-height: 1.35; }}
    h1, h2 {{ color:#55ff8a; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
    .metric {{ border:1px solid #1dd35b; padding:10px; border-radius:4px; }}
    .segment-board {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:12px; margin:14px 0 22px; }}
    .segment-card {{ border:1px solid #1dd35b; background:#030806; border-radius:4px; padding:10px; min-height:120px; }}
    .segment-card h3 {{ margin:0 0 4px; color:#7cff9b; font-size:1em; }}
    .segment-card ul {{ margin:10px 0 0; padding-left:18px; }}
    .segment-card li {{ margin:5px 0; }}
    .segment-meta, .asset-meta {{ color:#9eeeb4; font-size:.86em; }}
    .asset-name {{ display:block; color:#28ff72; font-weight:bold; }}
    table {{ width:100%; border-collapse:collapse; margin: 12px 0 24px; }}
    th, td {{ border:1px solid #146b33; padding:7px; vertical-align:top; }}
    th {{ background:#0d2716; text-align:left; }}
    .note {{ color:#b9ffc9; max-width: 980px; }}
  </style>
</head>
<body>
  <h1>Guppy ICS Segmentation Assessment</h1>
  <section>
    <h2>Executive Summary</h2>
    <div class="grid">
      <div class="metric">Assets discovered<br><strong>{summary['assets']}</strong></div>
      <div class="metric">Assets classified<br><strong>{summary['classified_assets']}</strong></div>
      <div class="metric">Candidate segments<br><strong>{summary['candidate_segments']}</strong></div>
      <div class="metric">Cross-segment relationships<br><strong>{summary['cross_segment_relationships']}</strong></div>
      <div class="metric">Segmentation posture<br><strong>{_h(assessment.posture.upper())}</strong></div>
      <div class="metric">Assessment confidence<br><strong>{_h(assessment.assessment_confidence.upper())}</strong></div>
    </div>
  </section>
  <section>
    <h2>Scope and Limitations</h2>
    <p class="note">This assessment is based on observed packet data and enriched asset identity already available to Guppy. Candidate segments are inferred. Unseen communication may still be legitimate or required, and absence of traffic is not proof that blocking it is safe. Physical and logical enforcement controls cannot always be verified from PCAP evidence.</p>
    <p class="note">Recommended segmentation and firewall intent must be validated against operational, engineering and safety requirements before implementation.</p>
  </section>
  <section>
    <h2>Segment Topology Overview</h2>
    <p class="note">Candidate segments are inferred from passive asset and communication evidence. Device names are shown where Guppy or OADS knows them; otherwise the best observed identifier is shown.</p>
    <div class="segment-board">{''.join(overview_cards)}</div>
    <h3>Observed Cross-Segment Paths</h3>
    <table><thead><tr><th>Source Segment</th><th>Destination Segment</th><th>Protocols</th><th>Assessment</th><th>Risk</th></tr></thead><tbody>{''.join(path_rows) if path_rows else '<tr><td colspan="5">No cross-segment paths observed.</td></tr>'}</tbody></table>
  </section>
  <section>
    <h2>Candidate Segments</h2>
    <table><thead><tr><th>Name</th><th>Category</th><th>Asset Count</th><th>Devices</th><th>Confidence</th><th>Basis</th></tr></thead><tbody>{''.join(segment_rows)}</tbody></table>
  </section>
  <section>
    <h2>Asset Classification</h2>
    <table><thead><tr><th>Device</th><th>Identifiers</th><th>Functional Category</th><th>Role</th><th>Vendor</th><th>Protocols</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>{''.join(asset_rows)}</tbody></table>
  </section>
  <section>
    <h2>Communication Matrix</h2>
    <table><thead><tr><th>Source Segment</th><th>Destination Segment</th><th>Protocol</th><th>Assessment</th><th>Recommendation</th></tr></thead><tbody>{''.join(matrix_rows)}</tbody></table>
  </section>
  <section>
    <h2>Segmentation Findings</h2>
    <table><thead><tr><th>Severity</th><th>Finding</th><th>Source Device</th><th>Destination Device</th><th>Assessment</th><th>Protocol</th><th>Recommendation</th><th>Evidence</th></tr></thead><tbody>{''.join(findings_rows)}</tbody></table>
  </section>
  <section>
    <h2>Recommended Communication Policy</h2>
    <table><thead><tr><th>Action</th><th>Source Segment</th><th>Destination Segment</th><th>Protocol</th><th>Transport</th><th>Destination Port</th><th>Reason</th></tr></thead><tbody>{''.join(firewall_rows)}</tbody></table>
  </section>
  <section>
    <h2>Standards Context</h2>
    <p class="note">The methodology is compatible with common OT segmentation concepts such as functional grouping, controlled communication paths, least privilege, restricted data flow, and defence in depth. It is not an IEC 62443 compliance checker and does not claim pass/fail status.</p>
  </section>
</body>
</html>
"""


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(to_plain(value), indent=2), encoding="utf-8")


def _write_matrix_csv(path: Path, assessment: SegmentationAssessment) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["source_segment", "destination_segment", "protocol", "assessment", "recommendation"])
        writer.writeheader()
        for rec in assessment.communication_recommendations:
            writer.writerow(
                {
                    "source_segment": rec.source_segment,
                    "destination_segment": rec.destination_segment,
                    "protocol": rec.protocol,
                    "assessment": rec.assessment,
                    "recommendation": rec.recommendation,
                }
            )


def _write_firewall_csv(path: Path, assessment: SegmentationAssessment) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["action", "source_segment", "destination_segment", "protocol", "transport", "destination_port", "reason"],
        )
        writer.writeheader()
        for intent in assessment.firewall_intent:
            writer.writerow(
                {
                    "action": intent.action,
                    "source_segment": intent.source_segment,
                    "destination_segment": intent.destination_segment,
                    "protocol": intent.protocol,
                    "transport": intent.transport or "",
                    "destination_port": intent.destination_port or "",
                    "reason": intent.reason,
                }
            )


def _h(value: Any) -> str:
    return html.escape(str(value))


def _identifier_summary(identifiers: Dict[str, Any]) -> str:
    parts = []
    for key in ("hostname", "ip", "ipv6", "mac"):
        values = identifiers.get(key) or []
        if values:
            parts.append(f"{key.upper()}: {', '.join(str(value) for value in values)}")
    for key, values in sorted(identifiers.items()):
        if key in {"hostname", "ip", "ipv6", "mac"} or not values:
            continue
        parts.append(f"{key.upper()}: {', '.join(str(value) for value in values)}")
    return " | ".join(parts)


def _asset_display(assets_by_id: Dict[str, Any], asset_id: Any) -> str:
    if not asset_id:
        return ""
    asset = assets_by_id.get(str(asset_id))
    if not asset:
        return str(asset_id)
    identifiers = _identifier_summary(asset.identifiers)
    if identifiers:
        return f"{asset.name} ({identifiers})"
    return asset.name
