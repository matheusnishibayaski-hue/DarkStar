"""API do dashboard — métricas, trends, histórico e export."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response, StreamingResponse

from backend.database.db import (
    compute_metrics,
    get_scan_history,
    get_top_issues,
    summary_report,
    vulnerability_trend,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/metrics")
def api_metrics(days: int = Query(30, ge=1, le=365)):
    data = compute_metrics(days=days)
    return {
        "status": "ok",
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/vulnerability-trend")
def api_vulnerability_trend(days: int = Query(30, ge=1, le=365)):
    return {
        "status": "ok",
        "data": vulnerability_trend(days=days),
        "period_days": days,
    }


@router.get("/top-issues")
def api_top_issues(limit: int = Query(10, ge=1, le=50)):
    issues = get_top_issues(limit=limit)
    return {"status": "ok", "data": issues, "count": len(issues)}


@router.get("/scan-history")
def api_scan_history(
    days: int = Query(30, ge=1, le=365),
    target: str | None = Query(None, max_length=256),
    limit: int = Query(100, ge=1, le=1000),
):
    scans = get_scan_history(days=days, target=target, limit=limit)
    return {
        "status": "ok",
        "data": scans,
        "count": len(scans),
        "filter": {"days": days, "target": target, "limit": limit},
    }


@router.get("/summary")
def api_summary(days: int = Query(30, ge=1, le=365)):
    return {"status": "ok", "summary": summary_report(days=days)}


@router.get("/export")
def api_export(
    format: str = Query("json", pattern="^(json|csv|pdf)$"),
    days: int = Query(30, ge=1, le=365),
):
    history = get_scan_history(days=days, limit=10000)
    metrics = compute_metrics(days=days)
    fmt = (format or "json").lower()

    if fmt == "json":
        return {
            "format": "json",
            "metrics": metrics,
            "history": history,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

    if fmt == "csv":
        output = io.StringIO()
        fields = [
            "target",
            "vulnerability_count",
            "critical",
            "high",
            "medium",
            "low",
            "timestamp",
            "status",
            "scan_type",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in history:
            writer.writerow({k: row.get(k) for k in fields})
        data = output.getvalue().encode("utf-8")
        return Response(
            content=data,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="darkstar-dashboard-{days}d.csv"'
            },
        )

    if fmt == "pdf":
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
        except ImportError as exc:
            raise HTTPException(status_code=500, detail="reportlab unavailable") from exc

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, 750, "DarkStar Security Dashboard")
        c.setFont("Helvetica", 11)
        y = 720
        lines = [
            f"Period: {days} days",
            f"Total scans: {metrics.get('total_scans', 0)}",
            f"Avg critical: {float(metrics.get('avg_critical') or 0):.1f}",
            f"Avg high: {float(metrics.get('avg_high') or 0):.1f}",
            f"Open vulnerabilities: {metrics.get('open_vulnerabilities', 0)}",
            f"Total findings (sum): {metrics.get('total_vulnerabilities', 0)}",
            "",
            "Recent targets:",
        ]
        for line in lines:
            c.drawString(50, y, line[:90])
            y -= 16
        for row in history[:15]:
            line = (
                f"- {row.get('target')} · vulns={row.get('vulnerability_count')} "
                f"crit={row.get('critical')} ({str(row.get('timestamp') or '')[:19]})"
            )
            c.drawString(50, y, line[:95])
            y -= 14
            if y < 60:
                c.showPage()
                y = 750
                c.setFont("Helvetica", 11)
        c.save()
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="darkstar-dashboard-{days}d.pdf"'
            },
        )

    raise HTTPException(status_code=400, detail="Invalid format")
