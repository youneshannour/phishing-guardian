from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from services.graph_service import build_graph_from_investigation
from services.scoring_service import compute_attack_surface
from services.timeline_service import build_timeline

BRAND_DARK = colors.HexColor("#0f172a") if REPORTLAB_AVAILABLE else None
BRAND_ACCENT = colors.HexColor("#3b82f6") if REPORTLAB_AVAILABLE else None
RISK_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#22c55e",
    "minimal": "#4ade80",
}


def report_status() -> Dict[str, Any]:
    return {
        "pdf_available": REPORTLAB_AVAILABLE,
        "engine": "reportlab" if REPORTLAB_AVAILABLE else None,
    }


def _esc(text: Any) -> str:
    if text is None:
        return ""
    s = str(text)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _fmt_duration(ms: int) -> str:
    if ms < 1000:
        return f"{ms} ms"
    return f"{ms / 1000:.1f} s"


def _fmt_date(iso: Optional[str]) -> str:
    if not iso:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M UTC")
    except ValueError:
        return iso[:19] if len(iso) >= 19 else iso


def prepare_report_context(investigation: Dict[str, Any]) -> Dict[str, Any]:
    """Agrège synthèse, score, timeline et graphe pour le rapport."""
    synth = investigation.get("synthesis") or {}
    attack_surface = synth.get("attack_surface") or compute_attack_surface(investigation)
    timeline = synth.get("timeline") or build_timeline(investigation)
    graph = build_graph_from_investigation(investigation)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "investigation": investigation,
        "target": investigation.get("target", "N/A"),
        "target_type": investigation.get("target_type", "unknown"),
        "playbook_name": investigation.get("playbook_name", "N/A"),
        "playbook_id": investigation.get("playbook_id", ""),
        "investigation_id": investigation.get("id", ""),
        "started_at": investigation.get("started_at"),
        "completed_at": investigation.get("completed_at"),
        "duration_ms": investigation.get("duration_ms", 0),
        "overall_risk": synth.get("overall_risk", "low"),
        "key_findings": synth.get("key_findings") or [],
        "tools_success": synth.get("tools_success", 0),
        "tools_failed": synth.get("tools_failed", 0),
        "entities_found": synth.get("entities_found", 0),
        "attack_surface": attack_surface,
        "timeline": timeline,
        "graph": graph,
        "steps": investigation.get("steps") or [],
        "entities": investigation.get("entities") or [],
    }


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "PGTitle",
            parent=base["Title"],
            fontSize=22,
            textColor=BRAND_DARK,
            spaceAfter=4,
            alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "PGSubtitle",
            parent=base["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=12,
        ),
        "h2": ParagraphStyle(
            "PGH2",
            parent=base["Heading2"],
            fontSize=13,
            textColor=BRAND_ACCENT,
            spaceBefore=14,
            spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "PGH3",
            parent=base["Heading3"],
            fontSize=10,
            textColor=BRAND_DARK,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "PGBody",
            parent=base["Normal"],
            fontSize=9,
            leading=13,
            textColor=BRAND_DARK,
        ),
        "bullet": ParagraphStyle(
            "PGBullet",
            parent=base["Normal"],
            fontSize=9,
            leading=12,
            leftIndent=12,
            bulletIndent=0,
            textColor=BRAND_DARK,
        ),
        "footer": ParagraphStyle(
            "PGFooter",
            parent=base["Normal"],
            fontSize=7,
            textColor=colors.HexColor("#94a3b8"),
            alignment=TA_CENTER,
        ),
        "meta": ParagraphStyle(
            "PGMeta",
            parent=base["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#475569"),
        ),
    }


def _header_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    canvas.drawString(2 * cm, 1.2 * cm, "Phishing Guardian OSINT — Rapport confidentiel")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    if doc.page == 1:
        canvas.setFillColor(BRAND_ACCENT)
        canvas.rect(0, A4[1] - 8 * mm, A4[0], 8 * mm, fill=1, stroke=0)
    canvas.restoreState()


def _meta_table(ctx: Dict[str, Any], st: Dict[str, ParagraphStyle]) -> Table:
    rows = [
        ["Cible", f"{ctx['target']} ({ctx['target_type']})"],
        ["Playbook", ctx["playbook_name"]],
        ["ID investigation", ctx["investigation_id"] or "—"],
        ["Début", _fmt_date(ctx["started_at"])],
        ["Fin", _fmt_date(ctx["completed_at"])],
        ["Durée", _fmt_duration(ctx["duration_ms"])],
        ["Risque global", ctx["overall_risk"].upper()],
        ["Généré le", _fmt_date(ctx["generated_at"])],
    ]
    data = [[Paragraph(f"<b>{_esc(a)}</b>", st["body"]), Paragraph(_esc(b), st["body"])] for a, b in rows]
    t = Table(data, colWidths=[4.2 * cm, 12.3 * cm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return t


def _attack_surface_section(ctx: Dict[str, Any], st: Dict[str, ParagraphStyle]) -> List[Any]:
    as_data = ctx["attack_surface"]
    if not as_data:
        return []
    flow: List[Any] = [Paragraph("Attack Surface Score", st["h2"])]
    color = as_data.get("color", "#3b82f6")
    score = as_data.get("score", 0)
    grade = as_data.get("grade_label", "N/A")
    flow.append(
        Paragraph(
            f'<font color="{color}"><b>{score}/100</b></font> — { _esc(as_data.get("summary", "")) }',
            st["body"],
        )
    )
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(f"<b>Niveau :</b> {_esc(grade)}", st["body"]))

    factors = as_data.get("factors") or []
    if factors:
        frows = [["Facteur", "Score", "Détail"]]
        for f in factors:
            frows.append([
                _esc(f.get("label", "")),
                f"{f.get('score', 0)}/{f.get('max_score', 0)}",
                _esc(f.get("details", ""))[:120],
            ])
        ft = Table(frows, colWidths=[4 * cm, 2 * cm, 10.5 * cm])
        ft.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        flow.append(Spacer(1, 6))
        flow.append(ft)

    recs = as_data.get("recommendations") or []
    if recs:
        flow.append(Spacer(1, 6))
        flow.append(Paragraph("Recommandations", st["h3"]))
        for r in recs:
            flow.append(Paragraph(f"• {_esc(r)}", st["bullet"]))
    return flow


def _findings_section(ctx: Dict[str, Any], st: Dict[str, ParagraphStyle]) -> List[Any]:
    findings = ctx["key_findings"]
    if not findings:
        return []
    flow: List[Any] = [Paragraph("Constats clés", st["h2"])]
    for f in findings:
        flow.append(Paragraph(f"• {_esc(f)}", st["bullet"]))
    return flow


def _timeline_section(ctx: Dict[str, Any], st: Dict[str, ParagraphStyle]) -> List[Any]:
    tl = ctx["timeline"]
    events = (tl or {}).get("events") or []
    if not events:
        return []
    flow: List[Any] = [Paragraph("Timeline d'activité", st["h2"])]
    insights = (tl.get("patterns") or {}).get("insights") or []
    for ins in insights[:3]:
        flow.append(Paragraph(f"• {_esc(ins)}", st["bullet"]))
    if insights:
        flow.append(Spacer(1, 4))

    sorted_ev = sorted(events, key=lambda e: e.get("date") or "", reverse=True)[:15]
    erows = [["Date", "Type", "Source", "Description"]]
    for ev in sorted_ev:
        erows.append([
            _esc(ev.get("date", "")),
            _esc(ev.get("event_type", "")),
            _esc(ev.get("source_label") or ev.get("source", "")),
            _esc(ev.get("title") or ev.get("description", ""))[:80],
        ])
    et = Table(erows, colWidths=[2.5 * cm, 2.8 * cm, 2.5 * cm, 8.7 * cm])
    et.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    flow.append(et)
    if len(events) > 15:
        flow.append(Paragraph(f"<i>… et {len(events) - 15} événement(s) supplémentaire(s)</i>", st["meta"]))
    return flow


def _graph_section(ctx: Dict[str, Any], st: Dict[str, ParagraphStyle]) -> List[Any]:
    graph = ctx["graph"]
    nodes = (graph or {}).get("nodes") or []
    edges = (graph or {}).get("edges") or []
    if not nodes:
        return []
    flow: List[Any] = [Paragraph("Graphe de relations", st["h2"])]
    flow.append(
        Paragraph(
            f"{len(nodes)} nœud(s), {len(edges)} lien(s) — vue textuelle des entités connectées.",
            st["body"],
        )
    )
    nrows = [["Entité", "Type", "Source"]]
    for n in nodes[:20]:
        nrows.append([
            _esc(n.get("label", "")),
            _esc(n.get("type", "")),
            _esc(n.get("source") or ("racine" if n.get("is_root") else "—")),
        ])
    nt = Table(nrows, colWidths=[7 * cm, 3 * cm, 6.5 * cm])
    nt.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    flow.append(Spacer(1, 4))
    flow.append(nt)
    if edges:
        flow.append(Spacer(1, 6))
        flow.append(Paragraph("Relations", st["h3"]))
        for e in edges[:12]:
            flow.append(
                Paragraph(
                    f"• {_esc(e.get('source', ''))} → {_esc(e.get('target', ''))} "
                    f"({_esc(e.get('label') or e.get('relation', ''))})",
                    st["bullet"],
                )
            )
    return flow


def _pipeline_section(ctx: Dict[str, Any], st: Dict[str, ParagraphStyle]) -> List[Any]:
    steps = ctx["steps"]
    if not steps:
        return []
    flow: List[Any] = [Paragraph("Pipeline d'investigation", st["h2"])]
    srows = [["Outil", "Statut", "Durée", "Résumé"]]
    for step in steps:
        status = step.get("status", "")
        summary = _step_summary(step)
        srows.append([
            _esc(step.get("plugin_name", "")),
            _esc(status),
            f"{step.get('duration_ms', 0)} ms",
            _esc(summary),
        ])
    st_table = Table(srows, colWidths=[3.5 * cm, 2 * cm, 2 * cm, 9 * cm])
    st_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    flow.append(st_table)
    return flow


def _entities_section(ctx: Dict[str, Any], st: Dict[str, ParagraphStyle]) -> List[Any]:
    entities = ctx["entities"]
    if not entities:
        return []
    flow: List[Any] = [Paragraph(f"Entités découvertes ({len(entities)})", st["h2"])]
    erows = [["Type", "Valeur", "Source", "Confiance"]]
    for e in entities[:25]:
        erows.append([
            _esc(e.get("type", "")),
            _esc(e.get("value", "")),
            _esc(e.get("source", "")),
            f"{int((e.get('confidence') or 1) * 100)}%",
        ])
    et = Table(erows, colWidths=[2.5 * cm, 6.5 * cm, 4.5 * cm, 2 * cm])
    et.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    flow.append(et)
    return flow


def _step_summary(step: Dict[str, Any]) -> str:
    if step.get("status") != "success":
        return step.get("error") or step.get("status", "")
    d = step.get("data") or {}
    pid = step.get("plugin_id", "")
    if pid == "leakcheck":
        return f"{d.get('breach_count', 0)} fuite(s), risque {d.get('risk_level', 'N/A')}"
    if pid == "sherlock":
        return f"{d.get('count', 0)} profil(s)"
    if pid == "virustotal":
        return f"{d.get('detections', 0)}/{d.get('total', 0)} détections AV"
    if pid == "abuseipdb":
        return f"Réputation {d.get('abuseConfidence', 0)}%"
    if pid in ("shodan_ip", "shodan_search"):
        return f"{len(d.get('ports') or [])} port(s), {d.get('vuln_count', 0)} CVE"
    if pid == "whois":
        inner = d.get("data") or {}
        return f"Type {d.get('type', 'N/A')}, org {inner.get('org') or inner.get('asn_org') or 'N/A'}"
    return "Données collectées"


def generate_pdf_bytes(investigation: Dict[str, Any]) -> bytes:
    """Génère un rapport PDF professionnel depuis un résultat d'investigation."""
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab non installé — pip install reportlab")

    ctx = prepare_report_context(investigation)
    st = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2.2 * cm,
        bottomMargin=1.8 * cm,
        title=f"Rapport OSINT — {ctx['target']}",
        author="Phishing Guardian",
    )

    story: List[Any] = []
    story.append(Paragraph("Rapport d'investigation OSINT", st["title"]))
    story.append(
        Paragraph(
            "Phishing Guardian — synthèse automatisée (playbooks, score, timeline, graphe)",
            st["subtitle"],
        )
    )
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 8))
    story.append(_meta_table(ctx, st))
    story.append(Spacer(1, 10))

    stats_text = (
        f"<b>{ctx['tools_success']}</b> outil(s) OK · "
        f"<b>{ctx['tools_failed']}</b> erreur(s) · "
        f"<b>{ctx['entities_found']}</b> entité(s)"
    )
    story.append(Paragraph(stats_text, st["body"]))

    for section_fn in (
        _findings_section,
        _attack_surface_section,
        _timeline_section,
        _graph_section,
        _pipeline_section,
        _entities_section,
    ):
        parts = section_fn(ctx, st)
        if parts:
            story.extend(parts)

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Ce rapport est généré automatiquement à partir de sources OSINT publiques. "
            "À usage informatif uniquement — vérifier les données avant toute action.",
            st["footer"],
        )
    )

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()


def suggested_filename(investigation: Dict[str, Any]) -> str:
    target = investigation.get("target", "investigation")
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in target)[:40]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return f"rapport-osint_{safe}_{ts}.pdf"
