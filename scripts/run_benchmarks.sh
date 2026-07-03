#!/usr/bin/env bash
# Run the Common Access Token benchmarks and generate a report with graphs.
# Outputs land in target/bench/ (report.md, *.svg, and report.pdf with --pdf).
#
# Usage:
#   scripts/run_benchmarks.sh            # full Criterion run (most accurate)
#   scripts/run_benchmarks.sh --quick    # short run for a fast sanity check
#   scripts/run_benchmarks.sh --pdf      # also render report.pdf (uses .venv + fpdf2)
#   scripts/run_benchmarks.sh --quick --pdf
#
# The markdown report and SVG charts use the system `python3` (no extra deps).
# The PDF needs `fpdf2`; since Homebrew's Python is externally managed (PEP 668),
# --pdf bootstraps a local virtualenv at .venv and installs fpdf2 there.
set -euo pipefail

cd "$(dirname "$0")/.."

VENV_DIR=".venv"

BENCH_ARGS=()
REPORT_ARGS=()
WANT_PDF=0
for arg in "$@"; do
  case "$arg" in
    --quick)
      # Shorter sampling for a quick look; less statistically robust.
      BENCH_ARGS=(-- --warm-up-time 0.5 --measurement-time 2 --sample-size 30)
      ;;
    --pdf)
      REPORT_ARGS+=(--pdf)
      WANT_PDF=1
      ;;
    *)
      echo "unknown option: $arg" >&2
      echo "usage: $0 [--quick] [--pdf]" >&2
      exit 64
      ;;
  esac
done

# Default to the system interpreter; switch to the venv's when a PDF is wanted.
PY="python3"
if [[ "$WANT_PDF" -eq 1 ]]; then
  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    echo "==> Creating virtualenv ($VENV_DIR) for PDF rendering"
    python3 -m venv "$VENV_DIR"
  fi
  # Install fpdf2 only if it isn't already present in the venv.
  if ! "$VENV_DIR/bin/python" -c "import fpdf" >/dev/null 2>&1; then
    echo "==> Installing fpdf2 into $VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet fpdf2
  fi
  PY="$VENV_DIR/bin/python"
fi

echo "==> Running benchmarks (cargo bench --bench cat)"
# Note the `+"..."` guard: on macOS's Bash 3.2, expanding an empty array under
# `set -u` errors with "unbound variable", so only expand when non-empty.
cargo bench --bench cat ${BENCH_ARGS[@]+"${BENCH_ARGS[@]}"}

echo "==> Generating report and graphs"
"$PY" scripts/bench_report.py ${REPORT_ARGS[@]+"${REPORT_ARGS[@]}"}

echo "==> Done. See target/bench/report.md"
