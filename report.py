"""PDF report generation for StealthOps."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def _safe(text: str) -> str:
    """Strip ANSI codes and coerce to Latin-1 for fpdf core fonts."""
    return _strip_ansi(text).encode("latin-1", errors="replace").decode("latin-1")


def _resolve_path(target: str, out_path: str | None) -> Path:
    if out_path:
        return Path(out_path).expanduser().resolve()
    safe_target = re.sub(r'[^\w.\-]', '_', target)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    downloads = Path.home() / "Downloads"
    base_dir = downloads if downloads.is_dir() else Path.home()
    return base_dir / f"stealthops-{safe_target}-{ts}.pdf"


def generate_report(
    target: str,
    result: dict[str, Any],
    out_path: str | None = None,
    route_mode: str = "public",
) -> Path:
    """Generate a PDF report from a query result dict. Returns the saved file path."""
    try:
        from fpdf import FPDF
    except ImportError as exc:
        raise RuntimeError(
            "PDF generation requires fpdf2. Install with: pip install fpdf2"
        ) from exc

    from formatter import format_cli_report

    body_text = _safe(format_cli_report(result))
    ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    class _Doc(FPDF):
        def footer(self) -> None:
            self.set_y(-12)
            self.set_font("Helvetica", "I", 7)
            self.set_text_color(150, 150, 150)
            self.cell(
                0, 6,
                txt=_safe(f"Page {self.page_no()}  |  StealthOps  |  {target}"),
                align="C",
                new_x="LMARGIN",
                new_y="NEXT",
            )

    pdf = _Doc(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(left=12, top=12, right=12)
    pdf.add_page()

    # Title block
    pdf.set_fill_color(24, 24, 24)
    pdf.set_text_color(220, 220, 220)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 9, txt="StealthOps  Intelligence Report", fill=True,
             new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 6,
             txt=_safe(f"Target: {target}   |   Generated: {ts_str}   |   Route: {route_mode}"),
             fill=True, new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    # Body lines
    for raw_line in body_text.splitlines():
        line = raw_line.replace("\t", "    ")
        if line.startswith("==="):
            section_label = line.strip().strip("=").strip()
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(55, 55, 55)
            pdf.set_text_color(240, 240, 240)
            pdf.cell(0, 6, txt=section_label, fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(20, 20, 20)
            pdf.ln(1)
        elif not line.strip():
            pdf.ln(2)
        else:
            if len(line) > 140:
                line = line[:137] + "..."
            pdf.set_font("Courier", "", 7.5)
            pdf.cell(0, 4.5, txt=line, new_x="LMARGIN", new_y="NEXT")

    dest = _resolve_path(target, out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(dest))
    return dest
