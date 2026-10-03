"""Recreate the comparison from retained observations, without timing new searches.

From the repository root, install matplotlib==3.10.6 in a separate plotting environment,
then run: python docs/visuals/plot_search_latency.py
The application itself does not need matplotlib.
"""

from __future__ import annotations

import json
from pathlib import Path
from statistics import mean, stdev

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, FuncFormatter

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent / "evidence" / "search-latency-results.json"
NAVY = "#253c59"
TEAL = "#087e8b"
INK = "#1d2d3c"
MUTED = "#536574"
GRID = "#dce4e9"


def main() -> None:
    data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rows = data["cases"]
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "axes.edgecolor": GRID,
            "axes.labelcolor": INK,
            "text.color": INK,
            "xtick.color": MUTED,
            "ytick.color": INK,
            "svg.fonttype": "none",
            "svg.hashsalt": "enigma-search-latency-v1",
        }
    )
    fig = plt.figure(figsize=(15.4, 8.6), facecolor="white")
    grid = fig.add_gridspec(
        1, 2, left=0.215, right=0.94, bottom=0.24, top=0.69, width_ratios=[1.45, 1], wspace=0.22
    )
    latency = fig.add_subplot(grid[0])
    ratios = fig.add_subplot(grid[1], sharey=latency)
    labels = [
        "5-letter message\nAll 5 letters known",
        "1-letter message\n1 letter known",
        "97-letter message\nFirst 12 letters known",
        "97-letter message\nLast 12 letters known",
    ]
    jitter = [-0.047, -0.023, 0, 0.023, 0.047]
    for y, row in enumerate(rows):
        for impl, color, offset in [("baseline", NAVY, -0.17), ("early", TEAL, 0.17)]:
            values = row["process_means_ms"][impl]
            center, spread = mean(values), stdev(values)
            assert abs(center - row["latency_summary_ms"][impl]["mean"]) < 1e-8
            latency.scatter(
                values, [y + offset + j for j in jitter], s=28, color=color, alpha=0.6, zorder=3
            )
            latency.errorbar(
                center,
                y + offset,
                xerr=spread,
                fmt="D",
                markersize=6.5,
                markerfacecolor="white",
                color=color,
                capsize=4,
                elinewidth=1.5,
                zorder=5,
            )
            latency.annotate(
                f"{center:,.1f} ms",
                (max(values) * 1.085, y + offset),
                va="center",
                fontsize=9,
                color=color,
            )
        pairs = row["paired_baseline_divided_by_early"]
        average = mean(pairs)
        assert abs(average - row["paired_ratio_summary"]["mean"]) < 1e-8
        ratios.scatter(pairs, [y + j for j in jitter], s=32, color=TEAL, alpha=0.58, zorder=3)
        ratios.errorbar(
            average,
            y,
            xerr=stdev(pairs),
            fmt="D",
            markersize=7,
            markerfacecolor="white",
            color=TEAL,
            capsize=5,
            elinewidth=1.5,
            zorder=5,
        )
        ratios.annotate(
            f"{average:.3f}×",
            (average, y - 0.23),
            va="center",
            ha="center",
            fontsize=11,
            weight="bold",
        )
    for axis in (latency, ratios):
        axis.set_xscale("log")
        axis.set_ylim(3.58, -0.58)
        axis.grid(axis="x", color=GRID, alpha=0.8, zorder=0)
        axis.tick_params(axis="y", length=0, pad=12)
        axis.tick_params(axis="x", which="minor", bottom=False)
        axis.spines[["top", "left", "right"]].set_visible(False)
        axis.set_axisbelow(True)
        for y in (0.5, 1.5, 2.5):
            axis.axhline(y, color=GRID, lw=0.8, alpha=0.75)
    latency.set_yticks(range(4), labels)
    latency.set_xlim(90, 26000)
    latency.xaxis.set_major_locator(FixedLocator([100, 300, 1000, 3000, 10000]))
    latency.xaxis.set_major_formatter(FuncFormatter(lambda value, _position: f"{value:,.0f}"))
    latency.set_xlabel("Complete-search time · milliseconds · log scale", labelpad=12)
    latency.set_title("Observed API time", loc="left", pad=22, fontsize=13, weight="bold")
    ratios.set_xlim(0.45, 100)
    ratios.xaxis.set_major_locator(FixedLocator([0.5, 1, 3, 10, 30, 100]))
    ratios.xaxis.set_major_formatter(FuncFormatter(lambda value, _position: f"{value:g}×"))
    ratios.tick_params(labelleft=False)
    ratios.axvline(1, color=INK, ls=(0, (3, 3)), lw=1.3)
    ratios.set_xlabel("Baseline ÷ early rejection · log scale", labelpad=12)
    ratios.set_title("Paired time ratios", loc="left", pad=22, fontsize=13, weight="bold")
    ratios.text(
        0,
        1.005,
        "Below 1× = early slower; above 1× = early faster",
        transform=ratios.transAxes,
        fontsize=9,
        color=MUTED,
    )

    fig.text(0.06, 0.94, "ENIGMA LAB  /  SEARCH EXPERIMENT", fontsize=11, color=TEAL, weight="bold")
    fig.text(
        0.06,
        0.884,
        "Search cost depends on where the known fragment appears",
        fontsize=21,
        weight="bold",
    )
    fig.text(
        0.06,
        0.835,
        "Every call checks all 17,576 starting windows. Rotor order, rings, reflector and plugboard remain fixed.",
        fontsize=12,
        color=MUTED,
    )
    fig.legend(
        handles=[
            Line2D([0], [0], color=NAVY, marker="o", lw=0, label="Corrected full-message baseline"),
            Line2D([0], [0], color=TEAL, marker="o", lw=0, label="Early-mismatch rejection"),
            Line2D(
                [0],
                [0],
                color=MUTED,
                marker="D",
                markerfacecolor="white",
                lw=1,
                label="Mean ± sample SD; small dots are process observations",
            ),
        ],
        loc="upper left",
        bbox_to_anchor=(0.052, 0.795),
        ncol=3,
        frameon=False,
        fontsize=10,
        columnspacing=2.2,
    )
    fig.text(
        0.06,
        0.15,
        "40 fresh processes · 80 timed calls · one warm-up + two timed calls per process · five process pairs per workload",
        fontsize=11,
        weight="bold",
    )
    fig.text(
        0.06,
        0.105,
        "47.304× is the mean of five paired ratios for the early-fragment case only. The one-letter and late-fragment means were higher.",
        fontsize=10.8,
    )
    fig.text(
        0.06,
        0.069,
        "One Windows / CPython 3.12 machine, one recorded run. SD shows between-process spread, not confidence intervals. No browser latency claim.",
        fontsize=10,
        color=MUTED,
    )
    fig.text(
        0.06,
        0.037,
        "Source: docs/evidence/search-latency-results.json · recorded 4 Oct 2026 (Singapore) · all four workloads retained",
        fontsize=9,
        color=MUTED,
    )
    fig.savefig(HERE / "search-latency-comparison.png", dpi=160, facecolor="white")
    fig.savefig(HERE / "search-latency-comparison.svg", facecolor="white", metadata={"Date": None})
    plt.close(fig)
    print("Wrote search-latency-comparison.png and .svg from the retained observations.")


if __name__ == "__main__":
    main()
