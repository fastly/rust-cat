#!/usr/bin/env python3
"""Generate a markdown report and SVG graphs from CAT benchmark results.

Reads the timing data Criterion writes under ``target/criterion`` and the
signature/token size data ``benches/cat.rs`` writes to
``target/bench/sizes.json``, then produces:

    target/bench/report.md          — a shareable markdown report
    target/bench/signing_time.svg   — signing time per algorithm (bar chart)
    target/bench/verification_time.svg
    target/bench/signature_size.svg
    target/bench/token_size.svg

The markdown report and SVG charts have **no third-party dependencies** — they
run on a stock Python 3 install and the SVGs render inline on GitHub.

With ``--pdf`` it also renders ``target/bench/report.pdf``. This is the only
feature that needs a package: ``fpdf2`` (pure Python, no native libs), so the
PDF path works in CI with a plain ``pip3 install fpdf2`` and no browser.

Usage:
    cargo bench --bench cat      # produce the raw data first
    python3 scripts/bench_report.py [--pdf]
"""

from __future__ import annotations

import json
import os
import sys

# Algorithms in the order we want them displayed.
ALGORITHMS = ["HS256", "ES256", "PS256"]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRITERION_DIR = os.path.join(ROOT, "target", "criterion")
SIZES_PATH = os.path.join(ROOT, "target", "bench", "sizes.json")
OUT_DIR = os.path.join(ROOT, "target", "bench")


def read_timing(group: str, alg: str) -> dict | None:
    """Return timing stats (in nanoseconds) for one Criterion benchmark.

    Criterion stores the latest run under ``<group>/<alg>/new/estimates.json``.
    Returns ``None`` if that benchmark hasn't been run yet.
    """
    path = os.path.join(CRITERION_DIR, group, alg, "new", "estimates.json")
    if not os.path.isfile(path):
        return None
    with open(path) as fh:
        data = json.load(fh)
    return {
        "mean_ns": data["mean"]["point_estimate"],
        "median_ns": data["median"]["point_estimate"],
        "stderr_ns": data["mean"]["standard_error"],
    }


def read_sizes() -> dict[str, dict]:
    """Return ``{alg: {signature_bytes, token_bytes}}`` from sizes.json."""
    if not os.path.isfile(SIZES_PATH):
        return {}
    with open(SIZES_PATH) as fh:
        data = json.load(fh)
    return {e["algorithm"]: e for e in data.get("sizes", [])}


def fmt_time(ns: float) -> str:
    """Human-friendly duration from a nanosecond value."""
    if ns < 1_000:
        return f"{ns:.1f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} µs"
    return f"{ns / 1_000_000:.3f} ms"


# --- SVG bar chart -----------------------------------------------------------

# Distinct fill per algorithm so charts are readable in the report.
BAR_COLORS = {
    "HS256": "#4e79a7",
    "ES256": "#59a14f",
    "PS256": "#e15759",
}


def svg_bar_chart(title: str, unit: str, values: list[tuple[str, float, str]]) -> str:
    """Render a horizontal bar chart as a standalone SVG string.

    ``values`` is a list of ``(label, numeric_value, display_text)`` tuples.
    Bars are scaled to the largest value so relative magnitudes are obvious
    even across algorithms that differ by orders of magnitude.
    """
    width = 720
    row_h = 46
    top_pad = 56
    bottom_pad = 24
    left_pad = 80
    right_pad = 180
    height = top_pad + row_h * len(values) + bottom_pad
    max_val = max((v for _, v, _ in values), default=1.0) or 1.0
    bar_max = width - left_pad - right_pad

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="-apple-system, Segoe UI, Helvetica, Arial, sans-serif">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{width / 2:.0f}" y="30" text-anchor="middle" font-size="18" '
        f'font-weight="600" fill="#222">{title}</text>',
        f'<text x="{width / 2:.0f}" y="48" text-anchor="middle" font-size="12" '
        f'fill="#777">lower is better — {unit}</text>',
    ]

    for i, (label, value, display) in enumerate(values):
        y = top_pad + i * row_h + 8
        bar_w = max(2.0, bar_max * (value / max_val))
        color = BAR_COLORS.get(label, "#888888")
        parts.append(
            f'<text x="{left_pad - 10}" y="{y + 20}" text-anchor="end" '
            f'font-size="14" font-weight="600" fill="#333">{label}</text>'
        )
        parts.append(
            f'<rect x="{left_pad}" y="{y}" width="{bar_w:.1f}" height="28" '
            f'rx="3" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{left_pad + bar_w + 8:.1f}" y="{y + 20}" '
            f'font-size="13" fill="#333">{display}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)


def write(path: str, content: str) -> None:
    with open(path, "w") as fh:
        fh.write(content)
    print(f"wrote {os.path.relpath(path, ROOT)}")


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)

    sizes = read_sizes()
    sign = {a: read_timing("sign", a) for a in ALGORITHMS}
    verify = {a: read_timing("verify", a) for a in ALGORITHMS}

    have_timing = any(sign.values()) or any(verify.values())
    if not have_timing and not sizes:
        print(
            "No benchmark data found. Run `cargo bench --bench cat` first.",
            file=sys.stderr,
        )
        return 1

    # --- charts --------------------------------------------------------------
    # Build the chart data once (title, unit, and (label, value, display) rows)
    # so the same numbers drive both the SVG files and the PDF — no rendering
    # engine needed, since we draw the bars ourselves.
    charts: dict[str, dict] = {}

    if any(sign.values()):
        charts["signing_time"] = {
            "title": "CAT Signing Time",
            "unit": "mean per signature",
            "rows": [
                (a, sign[a]["mean_ns"], fmt_time(sign[a]["mean_ns"]))
                for a in ALGORITHMS
                if sign[a]
            ],
        }

    if any(verify.values()):
        charts["verification_time"] = {
            "title": "CAT Verification Time",
            "unit": "mean per verification",
            "rows": [
                (a, verify[a]["mean_ns"], fmt_time(verify[a]["mean_ns"]))
                for a in ALGORITHMS
                if verify[a]
            ],
        }

    if sizes:
        charts["signature_size"] = {
            "title": "CAT Signature Size",
            "unit": "raw signature/tag",
            "rows": [
                (a, sizes[a]["signature_bytes"], f'{sizes[a]["signature_bytes"]} bytes')
                for a in ALGORITHMS
                if a in sizes
            ],
        }
        charts["token_size"] = {
            "title": "CAT Encoded Token Size",
            "unit": "full CBOR token",
            "rows": [
                (a, sizes[a]["token_bytes"], f'{sizes[a]["token_bytes"]} bytes')
                for a in ALGORITHMS
                if a in sizes
            ],
        }

    for slug, ch in charts.items():
        write(
            os.path.join(OUT_DIR, f"{slug}.svg"),
            svg_bar_chart(ch["title"], ch["unit"], ch["rows"]),
        )

    # --- shared report content -----------------------------------------------
    intro = (
        "Performance of CAT signing and verification across all supported "
        "algorithms. Timing measured with Criterion; sizes captured directly "
        "from signed tokens."
    )
    # (label, slug) pairs, in display order, for the graph sections.
    graph_order = [
        ("Signing time", "signing_time"),
        ("Verification time", "verification_time"),
        ("Signature size", "signature_size"),
        ("Encoded token size", "token_size"),
    ]
    notes = [
        "**HS256** is a symmetric MAC (COSE_Mac0): fastest and smallest, but "
        "signer and verifier share the same secret.",
        "**ES256** (ECDSA P-256) and **PS256** (RSASSA-PSS) are asymmetric "
        "(COSE_Sign1): the verifier only needs the public key.",
        "All tokens carry an identical claim set so sizes and times are "
        "comparable across algorithms.",
        "Regenerate with `cargo bench --bench cat && python3 scripts/bench_report.py`.",
    ]
    # Summary table rows: (algorithm, signing, verification, sig size, token size).
    summary = []
    for a in ALGORITHMS:
        summary.append(
            (
                a,
                fmt_time(sign[a]["mean_ns"]) if sign[a] else "—",
                fmt_time(verify[a]["mean_ns"]) if verify[a] else "—",
                f'{sizes[a]["signature_bytes"]} B' if a in sizes else "—",
                f'{sizes[a]["token_bytes"]} B' if a in sizes else "—",
            )
        )

    # --- markdown report -----------------------------------------------------
    lines = [
        "# Common Access Token — Benchmark Report",
        "",
        intro.replace("with Criterion", "with [Criterion]"),
        "",
        "[Criterion]: https://github.com/bheisler/criterion.rs",
        "",
        "## Summary",
        "",
        "| Algorithm | Signing time | Verification time | Signature size | Token size |",
        "| --------- | -----------: | ----------------: | -------------: | ---------: |",
    ]
    lines += [f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |" for r in summary]
    lines += ["", "## Graphs", ""]
    for label, slug in graph_order:
        if slug in charts:
            lines += [f"### {label}", "", f"![{label}]({slug}.svg)", ""]
    lines += ["## Notes", ""]
    lines += [f"- {n}" for n in notes]
    lines.append("")
    write(os.path.join(OUT_DIR, "report.md"), "\n".join(lines))

    # --- optional PDF --------------------------------------------------------
    if "--pdf" in sys.argv[1:]:
        pdf_path = os.path.join(OUT_DIR, "report.pdf")
        try:
            render_pdf(pdf_path, intro, summary, graph_order, charts, notes)
        except ImportError:
            print(
                "Could not render PDF: the `fpdf2` package is not installed.\n"
                "Install it with `pip3 install fpdf2`, then re-run with --pdf.",
                file=sys.stderr,
            )
            return 2
        print(f"wrote {os.path.relpath(pdf_path, ROOT)}")

    return 0


# --- PDF rendering (fpdf2) ---------------------------------------------------
# fpdf2 is a pure-Python package (no native dependencies), so the PDF path works
# anywhere `pip install fpdf2` succeeds — including CI without a browser. We draw
# the bar charts directly from the same numbers used for the SVGs.

# RGB equivalents of the SVG bar colors, keyed by algorithm.
PDF_BAR_COLORS = {
    "HS256": (78, 121, 167),
    "ES256": (89, 161, 79),
    "PS256": (225, 87, 89),
}


def render_pdf(
    pdf_path: str,
    intro: str,
    summary: list[tuple],
    graph_order: list[tuple[str, str]],
    charts: dict[str, dict],
    notes: list[str],
) -> None:
    """Render the report to PDF with fpdf2. Raises ImportError if unavailable."""
    from fpdf import FPDF  # imported lazily so the PDF dep stays optional

    pdf = FPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(18, 18, 18)
    pdf.add_page()
    epw = pdf.epw  # effective page width (inside margins)

    # Title.
    pdf.set_font("Helvetica", "B", 20)
    pdf.multi_cell(epw, 9, "Common Access Token - Benchmark Report")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(80)
    pdf.multi_cell(epw, 5.5, _ascii(intro))
    pdf.set_text_color(0)
    pdf.ln(4)

    # Summary table.
    _pdf_heading(pdf, "Summary")
    headers = [
        "Algorithm",
        "Signing time",
        "Verification time",
        "Signature size",
        "Token size",
    ]
    widths = [epw * w for w in (0.20, 0.22, 0.24, 0.18, 0.16)]
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(245)
    for head, w in zip(headers, widths):
        pdf.cell(w, 8, head, border=1, align="C", fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 10)
    for row in summary:
        for i, (cell, w) in enumerate(zip(row, widths)):
            pdf.cell(w, 7, _ascii(cell), border=1, align="L" if i == 0 else "R")
        pdf.ln()
    pdf.ln(4)

    # Graphs.
    _pdf_heading(pdf, "Graphs")
    for label, slug in graph_order:
        if slug in charts:
            _pdf_bar_chart(pdf, charts[slug], epw)

    # Notes.
    _pdf_heading(pdf, "Notes")
    pdf.set_font("Helvetica", "", 10)
    for note in notes:
        _pdf_note(pdf, note, epw)

    pdf.output(pdf_path)


def _pdf_heading(pdf, text: str) -> None:
    pdf.set_font("Helvetica", "B", 14)
    pdf.ln(2)
    pdf.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _pdf_bar_chart(pdf, chart: dict, epw: float) -> None:
    """Draw one horizontal bar chart at the current cursor position."""
    rows = chart["rows"]
    max_val = max((v for _, v, _ in rows), default=1.0) or 1.0
    label_w = 22  # mm reserved for the algorithm label
    value_w = 30  # mm reserved for the value text on the right
    bar_max = epw - label_w - value_w
    row_h = 9

    # Keep the whole chart (title + bars) on one page.
    needed = 14 + row_h * len(rows)
    if pdf.get_y() + needed > pdf.page_break_trigger:
        pdf.add_page()

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, _ascii(chart["title"]), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(120)
    pdf.cell(0, 4, _ascii(f"lower is better - {chart['unit']}"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0)

    x0 = pdf.l_margin
    for label, value, display in rows:
        y = pdf.get_y()
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_xy(x0, y)
        pdf.cell(label_w, row_h, _ascii(label), align="L")
        bar_w = max(0.6, bar_max * (value / max_val))
        r, g, b = PDF_BAR_COLORS.get(label, (136, 136, 136))
        pdf.set_fill_color(r, g, b)
        pdf.rect(x0 + label_w, y + 1.5, bar_w, row_h - 3, style="F")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_xy(x0 + label_w + bar_w + 1.5, y)
        pdf.cell(value_w, row_h, _ascii(display), align="L")
        pdf.set_y(y + row_h)
    pdf.ln(3)


def _pdf_note(pdf, note: str, epw: float) -> None:
    """Render one bullet note, honoring **bold** and `code` spans."""
    pdf.cell(4, 5.5, "-")
    x_start = pdf.get_x()
    # Split into (text, is_bold, is_code) runs.
    for text, bold, code in _md_runs(note):
        style = "B" if bold else ""
        pdf.set_font("Courier" if code else "Helvetica", style, 10)
        pdf.write(5.5, _ascii(text))
    pdf.ln(6)
    pdf.set_x(x_start - 4)


def _md_runs(text: str):
    """Yield (text, is_bold, is_code) runs from a tiny markdown subset."""
    # Code spans first (they win over bold), then bold within non-code parts.
    for i, code_part in enumerate(text.split("`")):
        if i % 2:  # inside backticks
            yield (code_part, False, True)
        else:
            for j, bold_part in enumerate(code_part.split("**")):
                if bold_part:
                    yield (bold_part, bool(j % 2), False)


def _ascii(text: str) -> str:
    """Map the few non-ASCII glyphs we use to ASCII for the core PDF fonts.

    fpdf2's built-in fonts are latin-1 only; the report uses an em dash and a
    micro sign, so substitute readable ASCII rather than ship a font file.
    """
    return (
        text.replace("—", "-")  # em dash
        .replace("µ", "u")  # micro sign (µs -> us)
        .replace("…", "...")
    )


if __name__ == "__main__":
    raise SystemExit(main())
