#!/usr/bin/env python3
from __future__ import annotations
import csv, math, shutil, subprocess
from pathlib import Path
from typing import Iterable, List, Tuple

Series = Tuple[str, List[float], List[float], str]


def _downsample(xs: List[float], ys: List[float], max_points: int = 160) -> Tuple[List[float], List[float]]:
    """Deterministic visual downsampling. CSVs remain the source of statistics."""
    if len(xs) <= max_points:
        return xs, ys
    keep = sorted(set(round(i * (len(xs) - 1) / (max_points - 1)) for i in range(max_points)))
    return [xs[i] for i in keep], [ys[i] for i in keep]


def _read_benchmark(root: Path) -> list[Series]:
    safe_x: List[float] = []
    safe_y: List[float] = []
    unsafe_x: List[float] = []
    unsafe_y: List[float] = []
    with (root / 'results' / 'benchmark.csv').open() as f:
        for r in csv.DictReader(f):
            x = float(r['patterns']); y = float(r['median_ms'])
            if r['unsafe_injected'] == 'True':
                unsafe_x.append(x); unsafe_y.append(y)
            else:
                safe_x.append(x); safe_y.append(y)
    return [('safe', safe_x, safe_y, 'solid'), ('unsafe', unsafe_x, unsafe_y, 'dashed')]


def _read_iac_cdf(root: Path) -> tuple[list[Series], dict[str, float]]:
    vals: List[float] = []
    with (root / 'results' / 'iac_rows.csv').open() as f:
        for r in csv.DictReader(f):
            vals.append(float(r['median_proxy_ms']))
    vals.sort()
    ys = [(i + 1) / len(vals) for i in range(len(vals))] if vals else []
    def quantile(q: float) -> float:
        if not vals:
            return 0.0
        i = min(len(vals) - 1, max(0, math.ceil(q * len(vals)) - 1))
        return vals[i]
    return [('IaC roles', vals, ys, 'solid')], {'median': quantile(0.50), 'p95': quantile(0.95)}


def _fmt(x: float) -> str:
    if abs(x - round(x)) < 1e-9:
        return str(int(round(x)))
    return f"{x:.3f}".rstrip('0').rstrip('.')


def _poly(points: Iterable[Tuple[float, float]]) -> str:
    return ' -- '.join(f"({_fmt(x)},{_fmt(y)})" for x, y in points)


def _compile(out_base: Path, tex: str) -> None:
    tex_path = out_base.with_suffix('.tex')
    tex_path.write_text(tex)
    subprocess.run(['pdflatex', '-interaction=nonstopmode', '-halt-on-error', tex_path.name], cwd=out_base.parent, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for ext in ['.aux', '.log']:
        p = out_base.with_suffix(ext)
        if p.exists():
            p.unlink()
    if shutil.which('pdftocairo'):
        subprocess.run(['pdftocairo', '-svg', str(out_base.with_suffix('.pdf')), str(out_base.with_suffix('.svg'))], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _plot_xy(out_base: Path, title: str, xlabel: str, ylabel: str, series: list[Series], *,
             logx: bool, logy: bool, xticks: list[float], yticks: list[float]) -> None:
    # Single-column IEEE figure, tuned for legibility at 0.95\columnwidth.
    W, H = 7.8, 4.55
    L, B = 1.05, 0.78
    plotW, plotH = 5.92, 3.05
    all_x = [x for _, xs, _, _ in series for x in xs if x > 0]
    all_y = [y for _, _, ys, _ in series for y in ys if y > 0 or not logy]
    xmin, xmax = min(min(all_x), min(xticks)), max(max(all_x), max(xticks))
    ymin, ymax = min(min(all_y), min(yticks)), max(max(all_y), max(yticks))
    if logx:
        lxmin, lxmax = math.log(xmin, 2), math.log(xmax, 2)
        sx = lambda x: L + plotW * (math.log(max(x, xmin), 2) - lxmin) / (lxmax - lxmin)
    else:
        sx = lambda x: L + plotW * (x - xmin) / (xmax - xmin)
    if logy:
        lymin, lymax = math.log10(max(ymin, 1e-9)), math.log10(ymax)
        sy = lambda y: B + plotH * (math.log10(max(y, max(ymin, 1e-9))) - lymin) / (lymax - lymin)
    else:
        sy = lambda y: B + plotH * (y - ymin) / (ymax - ymin)
    body: list[str] = []
    body.append(r"\fill[black!2] (%s,%s) rectangle (%s,%s);" % (_fmt(L), _fmt(B), _fmt(L+plotW), _fmt(B+plotH)))
    for t in xticks:
        x = sx(t)
        body.append(r"\draw[black!22, line width=0.25pt] (%s,%s) -- (%s,%s);" % (_fmt(x), _fmt(B), _fmt(x), _fmt(B+plotH)))
        body.append(r"\draw[black, line width=0.25pt] (%s,%s) -- (%s,%s);" % (_fmt(x), _fmt(B), _fmt(x), _fmt(B-0.065)))
        body.append(r"\node[anchor=north] at (%s,%s) {%s};" % (_fmt(x), _fmt(B-0.09), _fmt(t)))
    for t in yticks:
        y = sy(t)
        body.append(r"\draw[black!22, line width=0.25pt] (%s,%s) -- (%s,%s);" % (_fmt(L), _fmt(y), _fmt(L+plotW), _fmt(y)))
        body.append(r"\draw[black, line width=0.25pt] (%s,%s) -- (%s,%s);" % (_fmt(L), _fmt(y), _fmt(L-0.065), _fmt(y)))
        body.append(r"\node[anchor=east] at (%s,%s) {%s};" % (_fmt(L-0.09), _fmt(y), _fmt(t)))
    body.append(r"\draw[black, line width=0.5pt] (%s,%s) rectangle (%s,%s);" % (_fmt(L), _fmt(B), _fmt(L+plotW), _fmt(B+plotH)))
    styles = {'solid': 'solid', 'dashed': 'densely dashed'}
    colors = ['black', 'black!55']
    marks = ['circle', 'rectangle']
    for idx, (label, xs, ys, style) in enumerate(series):
        xs, ys = _downsample(xs, ys)
        pts = [(sx(x), sy(y)) for x, y in zip(xs, ys) if (not logx or x > 0) and (not logy or y > 0)]
        body.append(r"\draw[%s, %s, line width=0.72pt] %s;" % (colors[idx % len(colors)], styles.get(style, 'solid'), _poly(pts)))
        # Mark only the original benchmark samples; dense CDF plots are rendered without marks.
        if len(pts) <= 16:
            for x, y in pts:
                if idx % 2 == 0:
                    body.append(r"\fill[%s] (%s,%s) circle (0.028);" % (colors[idx % len(colors)], _fmt(x), _fmt(y)))
                else:
                    d = 0.026
                    body.append(r"\fill[%s] (%s,%s) rectangle (%s,%s);" % (colors[idx % len(colors)], _fmt(x-d), _fmt(y-d), _fmt(x+d), _fmt(y+d)))
    body.append(r"\node[anchor=south] at (%s,%s) {\bfseries %s};" % (_fmt(L+plotW/2), _fmt(B+plotH+0.23), title))
    body.append(r"\node[anchor=north] at (%s,%s) {%s};" % (_fmt(L+plotW/2), _fmt(0.05), xlabel))
    body.append(r"\node[rotate=90, anchor=south] at (0.13,%s) {%s};" % (_fmt(B+plotH/2), ylabel))
    lx, ly = L + plotW - 1.55, B + 0.32
    for idx, (label, _, _, style) in enumerate(series):
        yy = ly + idx*0.30
        body.append(r"\draw[%s,%s,line width=0.75pt] (%s,%s) -- (%s,%s);" % (colors[idx % len(colors)], styles.get(style, 'solid'), _fmt(lx), _fmt(yy), _fmt(lx+0.40), _fmt(yy)))
        body.append(r"\node[anchor=west] at (%s,%s) {%s};" % (_fmt(lx+0.48), _fmt(yy), label))
    tex = r"""\documentclass[tikz,border=1pt]{standalone}
\usepackage{mathptmx}
\begin{document}
\begin{tikzpicture}[x=1cm,y=1cm]
\scriptsize
%s
\end{tikzpicture}
\end{document}
""" % ('\n'.join(body))
    _compile(out_base, tex)


def _plot_cdf(out_base: Path, title: str, xlabel: str, ylabel: str, series: list[Series], q: dict[str, float]) -> None:
    W, H = 7.8, 4.55
    L, B = 1.05, 0.78
    plotW, plotH = 5.92, 3.05
    xticks = [0.1, 1, 10, 30]
    yticks = [0, 0.5, 0.95, 1.0]
    all_x = [x for _, xs, _, _ in series for x in xs if x > 0]
    xmin, xmax = min(min(all_x), min(xticks)), max(max(all_x), max(xticks))
    lxmin, lxmax = math.log10(xmin), math.log10(xmax)
    sx = lambda x: L + plotW * (math.log10(max(x, xmin)) - lxmin) / (lxmax - lxmin)
    sy = lambda y: B + plotH * y
    body: list[str] = []
    body.append(r"\fill[black!2] (%s,%s) rectangle (%s,%s);" % (_fmt(L), _fmt(B), _fmt(L+plotW), _fmt(B+plotH)))
    for t in xticks:
        x = sx(t)
        body.append(r"\draw[black!22, line width=0.25pt] (%s,%s) -- (%s,%s);" % (_fmt(x), _fmt(B), _fmt(x), _fmt(B+plotH)))
        body.append(r"\draw[black, line width=0.25pt] (%s,%s) -- (%s,%s);" % (_fmt(x), _fmt(B), _fmt(x), _fmt(B-0.065)))
        body.append(r"\node[anchor=north] at (%s,%s) {%s};" % (_fmt(x), _fmt(B-0.09), _fmt(t)))
    for t in yticks:
        y = sy(t)
        body.append(r"\draw[black!22, line width=0.25pt] (%s,%s) -- (%s,%s);" % (_fmt(L), _fmt(y), _fmt(L+plotW), _fmt(y)))
        body.append(r"\draw[black, line width=0.25pt] (%s,%s) -- (%s,%s);" % (_fmt(L), _fmt(y), _fmt(L-0.065), _fmt(y)))
        body.append(r"\node[anchor=east] at (%s,%s) {%s};" % (_fmt(L-0.09), _fmt(y), _fmt(t)))
    body.append(r"\draw[black, line width=0.5pt] (%s,%s) rectangle (%s,%s);" % (_fmt(L), _fmt(B), _fmt(L+plotW), _fmt(B+plotH)))
    for label, xs, ys, style in series:
        xs, ys = _downsample(xs, ys)
        pts = [(sx(x), sy(y)) for x, y in zip(xs, ys) if x > 0]
        body.append(r"\draw[black, line width=0.78pt] %s;" % _poly(pts))
    median = q['median']; p95 = q['p95']
    for name, val, frac, dy in [('median', median, 0.50, 0.19), ('p95', p95, 0.95, -0.18)]:
        x = sx(val); y = sy(frac)
        body.append(r"\draw[black!55,densely dashed,line width=0.45pt] (%s,%s) -- (%s,%s) -- (%s,%s);" % (_fmt(L), _fmt(y), _fmt(x), _fmt(y), _fmt(x), _fmt(B)))
        body.append(r"\fill[black] (%s,%s) circle (0.025);" % (_fmt(x), _fmt(y)))
        labx = min(x + 0.18, L + plotW - 1.15)
        body.append(r"\node[anchor=west] at (%s,%s) {%s %.2f ms};" % (_fmt(labx), _fmt(y+dy), name, val))
    body.append(r"\node[anchor=south] at (%s,%s) {\bfseries %s};" % (_fmt(L+plotW/2), _fmt(B+plotH+0.23), title))
    body.append(r"\node[anchor=north] at (%s,%s) {%s};" % (_fmt(L+plotW/2), _fmt(0.05), xlabel))
    body.append(r"\node[rotate=90, anchor=south] at (0.13,%s) {%s};" % (_fmt(B+plotH/2), ylabel))
    tex = r"""\documentclass[tikz,border=1pt]{standalone}
\usepackage{mathptmx}
\begin{document}
\begin{tikzpicture}[x=1cm,y=1cm]
\scriptsize
%s
\end{tikzpicture}
\end{document}
""" % ('\n'.join(body))
    _compile(out_base, tex)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    out_dir = Path(__file__).resolve().parents[2] / 'paper' / 'figures'
    out_dir.mkdir(parents=True, exist_ok=True)
    _plot_xy(out_dir / 'benchmark', 'synthetic scaling', 'subject patterns', 'median analysis time (ms)', _read_benchmark(root), logx=True, logy=True, xticks=[1,2,4,8,16,32,64], yticks=[5,10,30,100,300])
    cdf, q = _read_iac_cdf(root)
    _plot_cdf(out_dir / 'iac_cdf', 'IaC analysis CDF', 'analysis time per role (ms)', 'cumulative fraction', cdf, q)
    print(f'Wrote deterministic Type-1 vector figures in {out_dir}', flush=True)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
