"""PDF report generation for authenticated SOC analysts."""

from __future__ import annotations

import os
from pathlib import Path
import uuid

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate

from app.models.database import get_logs


def generate_report(output_path: str | None = None) -> str:
    report_dir = Path(os.getenv("REPORT_DIR", "runtime"))
    report_dir.mkdir(parents=True, exist_ok=True)

    target = (
        Path(output_path)
        if output_path
        else report_dir / f"soc-report-{uuid.uuid4().hex}.pdf"
    )

    styles = getSampleStyleSheet()
    elements = []
    for log in get_logs():
        elements.append(
            Paragraph(
                f"{log[1]} | Risk: {log[2]} | Threat: {log[3]}",
                styles["Normal"],
            )
        )

    SimpleDocTemplate(str(target)).build(elements)
    return str(target)
