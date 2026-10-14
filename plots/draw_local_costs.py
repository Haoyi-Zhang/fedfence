"""Optional artifact renderer mechanically copied from the current paper renderer.

Reads retained measurements only. --output-dir (required) must be outside the
project. Derived DATs and PDFs are written only there. PDF drawing requires ReportLab;
validation and tests use only the standard library. Drawing requires
--font-root pointing to external TeX fonts; no font binaries are vendored.
No native measurements or full paper-table generation are run.

Geometry is constructed in Python with ReportLab. Labels use the installed
Linux Libertine 5.3 regular Type 1 font, embedded in full. Its ASCII advances
are retained beside this source. This is the native pdfLaTeX face and the
Type 1 counterpart of the XeLaTeX manuscript's OpenType Libertine face.
Font files are not vendored or relicensed.

Run from any directory with --font-root <TeX distribution fonts directory>.
Optional --column-width-pt follows the manuscript's actual TeX column width;
the default comes from its retained compilation log. TeX pt -> PDF bp is
72/72.27. Figure heights follow the original plotting declarations.
"""
import argparse
import csv
import math
import re
import hashlib
import json
import statistics
from decimal import Decimal
from pathlib import Path

pdfmetrics = None
canvas = None


def load_drawing_dependency():
    global pdfmetrics, canvas
    try:
        from reportlab.pdfbase import pdfmetrics as metrics
        from reportlab.pdfgen import canvas as pdf_canvas
    except ImportError as exc:
        raise RuntimeError("Optional PDF drawing requires ReportLab; install it in the selected drawing environment") from exc
    pdfmetrics, canvas = metrics, pdf_canvas

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent
FONT = "ManuscriptRoman"
PT = 72 / 72.27
CM = 72 / 2.54


def register_font(root):
    pfb = Path(root) / "type1/public/libertine/LinLibertineT.pfb"
    face = pdfmetrics.EmbeddedType1Face(
        str(HERE / "libertine-labels.afm"), str(pfb))
    pdfmetrics.registerTypeFace(face)
    font = pdfmetrics.Font(FONT, face.name, "WinAnsiEncoding")
    font.substitutionFonts = []  # Missing labels must not introduce Helvetica.
    pdfmetrics.registerFont(font)


def new_pdf(name, width, height, output_dir):
    return canvas.Canvas(str(output_dir / name), pagesize=(width, height),
                         initialFontName=FONT, initialFontSize=8,
                         pageCompression=1, invariant=1)


def text(c, x, y, label, size=8, align="center"):
    # The reviewed labels use ASCII; never silently substitute a font.
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in label):
        raise ValueError("Label requires explicit native glyph support")
    c.setFont(FONT, size)
    c.setFillColorRGB(0, 0, 0)
    if align == "left":
        c.drawString(x, y, label)
    elif align == "right":
        c.drawRightString(x, y, label)
    else:
        c.drawCentredString(x, y, label)


def axes(c, box, xrange, yrange, xticks, yticks, xlabel, ylabel,
         logx=False, logy=False, grid=True, ticksize=8, labelsize=9):
    left, bottom, width, height = box
    transform_x = math.log10 if logx else float
    transform_y = math.log10 if logy else float
    xa, xb = map(transform_x, xrange)
    ya, yb = map(transform_y, yrange)

    def xy(x, y):
        return (left + width * (transform_x(x) - xa) / (xb - xa),
                bottom + height * (transform_y(y) - ya) / (yb - ya))

    c.setLineWidth(.35)
    if grid:
        c.setStrokeColorRGB(.86, .86, .86)
        for value, _ in xticks:
            x, _ = xy(value, yrange[0])
            c.line(x, bottom, x, bottom + height)
        for value, _ in yticks:
            _, y = xy(xrange[0], value)
            c.line(left, y, left + width, y)
    c.setStrokeColorRGB(.28, .28, .28)
    c.rect(left, bottom, width, height, fill=0, stroke=1)
    for value, label in xticks:
        x, _ = xy(value, yrange[0])
        c.line(x, bottom, x, bottom - 3)
        text(c, x, bottom - 13, label, ticksize)
    for value, label in yticks:
        _, y = xy(xrange[0], value)
        c.line(left - 3, y, left, y)
        text(c, left - 6, y - 2.4, label, ticksize, "right")
    text(c, left + width / 2, bottom - 28, xlabel, labelsize)
    if ylabel:
        c.saveState()
        c.translate(left - 26, bottom + height / 2)
        c.rotate(90)
        text(c, 0, 0, ylabel, labelsize)
        c.restoreState()
    return xy


def legend(c, items, width, y, size=8):
    # Compact one-row native-font legend; no in-figure title or footer.
    lengths = [14 + pdfmetrics.stringWidth(name, FONT, size)
               for name, _ in items]
    total = sum(lengths) + 14 * (len(items) - 1)
    if total > width - 8:
        raise ValueError("Legend would exceed the figure width")
    x = (width - total) / 2
    c.setLineWidth(.5)
    for (name, colour), length in zip(items, lengths):
        c.setStrokeColorRGB(0, 0, 0)
        c.setFillColorRGB(*colour)
        c.rect(x, y, 8, 5, fill=1, stroke=1)
        text(c, x + 12, y - .1, name, size, "left")
        x += length + 14


def line_points(c, points, shape="circle", radius=1.8, connect=True):
    c.setStrokeColorRGB(0, 0, 0)
    c.setLineWidth(.6)
    if connect:
        p = c.beginPath()
        p.moveTo(*points[0])
        for point in points[1:]:
            p.lineTo(*point)
        c.drawPath(p)
    c.setFillColorRGB(1, 1, 1)
    for x, y in points:
        if shape == "square":
            c.rect(x - radius, y - radius, 2 * radius, 2 * radius,
                   fill=1, stroke=1)
        elif shape == "triangle":
            p = c.beginPath()
            p.moveTo(x, y + radius)
            p.lineTo(x - radius, y - radius)
            p.lineTo(x + radius, y - radius)
            p.close()
            c.drawPath(p, fill=1, stroke=1)
        else:
            c.circle(x, y, radius, fill=1, stroke=1)


def bars(c, xy, categories, series, colours, barwidth):
    for i, category in enumerate(categories):
        centre, baseline = xy(i, 0)
        for j, values in enumerate(series):
            top = xy(i, float(values[i]))[1]
            x = centre + (j - (len(series) - 1) / 2) * barwidth
            c.setFillColorRGB(*colours[j])
            c.setStrokeColorRGB(0, 0, 0)
            c.setLineWidth(.5)
            # Zero-height bars remain at baseline, never given invented height.
            c.rect(x - barwidth / 2, baseline, barwidth, top - baseline,
                   stroke=1, fill=1)


def table(path, delimiter=None):
    with path.open(newline="", encoding="utf-8") as stream:
        if delimiter:
            return list(csv.DictReader(stream, delimiter=delimiter))
        names = stream.readline().split()
        return [dict(zip(names, line.split())) for line in stream
                if line.strip()]



def require(condition, message):
    if not condition:
        raise ValueError(message)


def prepare_output_dir(path):
    path = Path(path).resolve()
    if path.is_relative_to(ARTIFACT.parent.resolve()):
        raise ValueError("--output-dir must be outside the project")
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError("--output-dir must be a fresh or empty directory")
    path.mkdir(parents=True, exist_ok=True)
    return path


def dat_text(rows, columns):
    return " ".join(columns) + "\n" + "".join(
        " ".join(row[column] for column in columns) + "\n" for row in rows)


SIZES = [1, 2, 4, 8, 16, 32]
TASKS = ("review-pass", "review-positive-loss", "receipt-replay")
EXPECTED_VERDICTS = {"review-pass": "pass", "review-positive-loss": "fail", "receipt-replay": "pass"}
CSV_FIELDS = ("required_tokens", "task", "repetition", "seconds", "expected", "verdict")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Nonfinite JSON number: " + value)


def load_scaling(folder):
    """Passively derive the selected retained series; never run full generation."""
    folder = Path(folder)
    record = json.loads((folder / "local_scaling.json").read_text(encoding="utf-8"),
                        object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    with (folder / "local_scaling.csv").open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        require(tuple(reader.fieldnames or ()) == CSV_FIELDS, "Unexpected/duplicate CSV header")
        rows = list(reader)
    validate_scaling(rows, record)
    require(isinstance(record["csv_sha256"], str) and
            re.fullmatch(r"[0-9a-f]{64}", record["csv_sha256"]) is not None and
            hashlib.sha256((folder / "local_scaling.csv").read_bytes()).hexdigest() == record["csv_sha256"],
            "Retained scaling CSV binding mismatch")
    # Keep generate_tosem_tables.py's float statistics and nine-decimal formatting.
    tables = {}
    for task, name in zip(TASKS, ("pass", "loss", "replay")):
        tables[f"scaling-{name}.dat"] = [
            {"n": str(row["required_tokens"]),
             "median": f'{row["median_seconds"]:.9f}',
             "lower": f'{row["median_seconds"]-row["min_seconds"]:.9f}',
             "upper": f'{row["max_seconds"]-row["median_seconds"]:.9f}'}
            for row in record["summary"] if row["task"] == task]
    return tables


def validate_scaling(rows, record):
    require(isinstance(record, dict) and record.get("schema") == "fedfence-local-scaling-v1"
            and record.get("passed") is True, "Invalid scaling record")
    for key, value in (("recorded_runs", 54), ("warmup_runs", 18), ("repetitions", 3)):
        require(type(record.get(key)) is int and record[key] == value, "Invalid denominator: " + key)
    require(record.get("sizes") == SIZES and
            all(type(n) is int for n in record["sizes"]), "Invalid retained sizes")
    require(len(rows) == 54 and all(set(row) == set(CSV_FIELDS) and
            all(isinstance(v, str) and v.strip() for v in row.values()) for row in rows),
            "Malformed/missing scaling rows")
    observations = {}
    for row in rows:
        require(row["required_tokens"] in tuple(map(str, SIZES)) and
                row["task"] in TASKS and row["repetition"] in ("0", "1", "2"),
                "Invalid size/task/repetition")
        key = (int(row["required_tokens"]), row["task"], int(row["repetition"]))
        require(key not in observations, "Duplicate scaling observation")
        try:
            seconds = float(row["seconds"])
        except ValueError as exc:
            raise ValueError("Invalid seconds") from exc
        require(math.isfinite(seconds) and seconds > 0, "Nonpositive/nonfinite seconds")
        require(row["verdict"] == row["expected"] == EXPECTED_VERDICTS[row["task"]],
                "Unexpected scaling judgment")
        observations[key] = seconds
    require(set(observations) == {(n,task,rep) for n in SIZES for task in TASKS for rep in (0,1,2)},
            "Incomplete scaling cell/repetition denominator")
    summary = record.get("summary")
    require(isinstance(summary,list) and len(summary)==18, "Expected 18 summary cells")
    cells = set()
    fields = {"required_tokens","task","repetitions","min_seconds","median_seconds","max_seconds"}
    for cell in summary:
        require(isinstance(cell,dict) and set(cell)==fields and
                type(cell["required_tokens"]) is int and cell["required_tokens"] in SIZES and
                cell["task"] in TASKS and type(cell["repetitions"]) is int and
                cell["repetitions"]==3, "Invalid summary cell")
        key = (cell["required_tokens"],cell["task"])
        require(key not in cells, "Duplicate summary cell")
        cells.add(key)
        values = [observations[(*key,rep)] for rep in (0,1,2)]
        for field, expected in (("min_seconds",min(values)),
                                ("median_seconds",statistics.median(values)),
                                ("max_seconds",max(values))):
            value = cell[field]
            require(type(value) in (int,float) and math.isfinite(value) and
                    value>0 and value==expected, "CSV/summary statistic disagreement: " + field)
    require(all([r["required_tokens"] for r in summary if r["task"]==task] == SIZES
                for task in TASKS), "Summary series order must retain all six sizes")


def main_args(default_width):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--input-dir", type=Path, default=ARTIFACT / "tosem/results",
                        help="Selected retained local_scaling.csv/json, not another native run")
    parser.add_argument("--column-width-pt", default=default_width, type=float)
    args = parser.parse_args()
    require(math.isfinite(args.column_width_pt) and args.column_width_pt * PT > 200,
            "Invalid manuscript width")
    return args


def draw(linewidth, processed, output_dir):
    specs = [("scaling-pass.dat", "Passing review", "circle"),
             ("scaling-loss.dat", "Positive loss", "square"),
             ("scaling-replay.dat", "Receipt replay", "triangle")]
    tables = [processed[source] for source, _, _ in specs]
    for rows in tables:
        require([row["n"] for row in rows] == ["1", "2", "4", "8", "16", "32"],
                "Retain every identity-size point in the original series order")
    # The original plot derived a common upper range from median + upper.
    ymax = max(Decimal(row["median"]) + Decimal(row["upper"])
               for rows in tables for row in rows) * Decimal("1.1")
    gap = .7 * CM
    panel = .29 * linewidth
    width = 3 * panel + 2 * gap
    height = .27 * linewidth
    c = new_pdf("local-costs.pdf", width, height, output_dir)
    for index, ((_, label, shape), rows) in enumerate(zip(specs, tables)):
        origin = index * (panel + gap)
        xy = axes(c, (origin + 33, 31, panel - 36, height - 51),
                  (.8, 40), (0, ymax),
                  [(n, str(n)) for n in (1, 2, 4, 8, 16, 32)],
                  [(n / 100, f"{n / 100:.2f}") for n in (0, 5, 10, 15, 20)],
                  "Identities", "Seconds" if index == 0 else "",
                  logx=True, ticksize=7, labelsize=8)
        # Panel identities are essential, not a redundant overall title.
        text(c, origin + 33 + (panel - 36) / 2, height - 9, label, 8.5)
        points = []
        c.setStrokeColorRGB(0, 0, 0)
        c.setLineWidth(.6)
        for row in rows:
            n, median = Decimal(row["n"]), Decimal(row["median"])
            low = median - Decimal(row["lower"])
            high = median + Decimal(row["upper"])
            x, lo = xy(n, low)
            _, hi = xy(n, high)
            c.line(x, lo, x, hi)
            c.line(x - 2, lo, x + 2, lo)
            c.line(x - 2, hi, x + 2, hi)
            points.append(xy(n, median))
        line_points(c, points, shape, radius=1.5)
    c.save()


if __name__ == "__main__":
    args = main_args(430.00462)
    tables = load_scaling(args.input_dir)
    load_drawing_dependency()
    register_font(args.font_root)
    output_dir = prepare_output_dir(args.output_dir)
    for name, rows in tables.items():
        (output_dir / name).write_text(dat_text(rows, ("n", "median", "lower", "upper")), encoding="utf-8", newline="\n")
    draw(args.column_width_pt * PT, tables, output_dir)
