"""PDF report generation for StealthOps."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Matches "Label: value" lines (with optional leading whitespace / "- " prefix)
_LABEL_VALUE_RE = re.compile(r'^(\s*(?:-\s+)?)([A-Za-z][^:\n]{0,45}?)(: )(.+)$')
# Matches standalone sub-section labels like "Registrant:" or "Name Servers:"
_SUBLABEL_RE = re.compile(r'^(\s*(?:-\s+)?)([A-Za-z][^:\n]{0,45}?):$')
# Matches enrichment provider headers like [virustotal]
_PROVIDER_HDR_RE = re.compile(r'^\[([a-zA-Z0-9_]+)\]$')

# Colors
_NAVY   = (15,  45,  90)   # title block
_TEAL   = (0,   75, 110)   # section headers
_TEAL_L = (215, 232, 240)  # provider sub-header background
_LIGHT  = (220, 235, 245)  # text on dark backgrounds
_BODY   = (20,  20,  20)   # body text


def _strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def _safe(text: str) -> str:
    """Strip ANSI codes and coerce to Latin-1 for PDF core fonts."""
    return _strip_ansi(text).encode("latin-1", errors="replace").decode("latin-1")


def _resolve_path(target: str, out_path: str | None) -> Path:
    if out_path:
        return Path(out_path).expanduser().resolve()
    safe_target = re.sub(r'[^\w.\-]', '_', target)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    downloads = Path.home() / "Downloads"
    base_dir = downloads if downloads.is_dir() else Path.home()
    return base_dir / f"stealthops-{safe_target}-{ts}.pdf"


def _load_fonts(pdf: Any) -> tuple[str, str]:
    """
    Try to load modern system fonts. Returns (header_font, mono_font).
    Falls back to Helvetica/Courier (always available as PDF core fonts).
    """
    win_fonts = Path("C:/Windows/Fonts")
    candidates = [
        (win_fonts / "segoeui.ttf",  win_fonts / "segoeuib.ttf",
         win_fonts / "consola.ttf",  win_fonts / "consolab.ttf",
         "SegoeUI", "Consolas"),
        (win_fonts / "calibri.ttf",  win_fonts / "calibrib.ttf",
         win_fonts / "consola.ttf",  win_fonts / "consolab.ttf",
         "Calibri", "Consolas"),
    ]
    for hf, hfb, mf, mfb, hname, mname in candidates:
        if all(p.is_file() for p in (hf, hfb, mf, mfb)):
            try:
                pdf.add_font(hname, "",  str(hf))
                pdf.add_font(hname, "B", str(hfb))
                pdf.add_font(mname, "",  str(mf))
                pdf.add_font(mname, "B", str(mfb))
                return hname, mname
            except Exception:
                pass
    return "Helvetica", "Courier"


def _section_label(line: str) -> str:
    """Extract readable label from a '=== SECTION ===  [source: ...]' line."""
    parts = [p.strip() for p in line.split("===") if p.strip()]
    if not parts:
        return line.strip()
    title = parts[0]
    if len(parts) >= 2:
        source = parts[1].strip("[] ").strip()
        return f"{title}  —  {source}"
    return title


def generate_report(
    target: str,
    result: dict[str, Any],
    out_path: str | None = None,
    route_mode: str = "public",
) -> Path:
    """Generate a PDF intelligence report from a query result dict. Returns the saved path."""
    try:
        from fpdf import FPDF
    except ImportError as exc:
        raise RuntimeError(
            "PDF generation requires fpdf2. Install with: pip install fpdf2"
        ) from exc

    from formatter import format_cli_report

    body_text = _safe(format_cli_report(result))
    ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    line_h = 4.5

    class _Doc(FPDF):
        def footer(self) -> None:
            self.set_y(-12)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(150, 150, 150)
            self.cell(0, 6, txt=_safe(f"Page {self.page_no()}  |  StealthOps  |  {target}"),
                      align="C", new_x="LMARGIN", new_y="NEXT")

    pdf = _Doc(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(left=12, top=12, right=12)

    hdr_font, mono_font = _load_fonts(pdf)

    pdf.add_page()

    # ---- Title block ----
    pdf.set_fill_color(*_NAVY)
    pdf.set_text_color(*_LIGHT)
    pdf.set_font(hdr_font, "B", 15)
    pdf.cell(0, 11, txt="StealthOps  Intelligence Report", fill=True,
             new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font(hdr_font, "", 8)
    pdf.cell(0, 7,
             txt=_safe(f"Target: {target}   |   Generated: {ts_str}   |   Route: {route_mode}"),
             fill=True, new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(*_BODY)
    pdf.ln(5)

    # ---- Body ----
    for raw_line in body_text.splitlines():
        line = raw_line.replace("\t", "    ")

        if line.startswith("==="):
            pdf.ln(1)
            pdf.set_font(hdr_font, "B", 9)
            pdf.set_fill_color(*_TEAL)
            pdf.set_text_color(*_LIGHT)
            pdf.cell(0, 6, txt=_section_label(line), fill=True,
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*_BODY)
            pdf.ln(1)

        elif _PROVIDER_HDR_RE.match(line):
            pdf.ln(1)
            pdf.set_font(hdr_font, "B", 8)
            pdf.set_fill_color(*_TEAL_L)
            pdf.set_text_color(*_TEAL)
            pdf.cell(0, 5, txt=line, fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*_BODY)
            pdf.ln(0.5)

        elif not line.strip():
            pdf.ln(2)

        else:
            if len(line) > 140:
                line = line[:137] + "..."

            lv = _LABEL_VALUE_RE.match(line)
            sl = _SUBLABEL_RE.match(line)

            if lv:
                prefix, label, _, value = lv.groups()
                if prefix:
                    pdf.set_font(mono_font, "", 7.5)
                    pdf.write(line_h, txt=prefix)
                pdf.set_font(mono_font, "B", 7.5)
                pdf.write(line_h, txt=label + ":")
                pdf.set_font(mono_font, "", 7.5)
                pdf.write(line_h, txt=" " + value)
                pdf.ln(line_h)
            elif sl:
                prefix, label = sl.groups()
                if prefix:
                    pdf.set_font(mono_font, "", 7.5)
                    pdf.write(line_h, txt=prefix)
                pdf.set_font(mono_font, "B", 7.5)
                pdf.write(line_h, txt=label + ":")
                pdf.ln(line_h)
            else:
                pdf.set_font(mono_font, "", 7.5)
                pdf.cell(0, line_h, txt=line, new_x="LMARGIN", new_y="NEXT")

    dest = _resolve_path(target, out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    import contextlib, io
    with contextlib.redirect_stderr(io.StringIO()):
        pdf.output(str(dest))
    return dest
