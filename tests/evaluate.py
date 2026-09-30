"""Run the labelled dataset through the detectors and print/save metrics.
Usage:  python -m tests.evaluate
"""
import json, os, sys, time
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.detectors import analyze
from tests.dataset import build

items = build()
by_cat = defaultdict(lambda: {"total": 0, "correct": 0})
misses = []
attacks_total = attacks_caught = benign_total = false_pos = 0

t0 = time.perf_counter()
for cat, prompt, expected in items:
    got = analyze(prompt).action
    ok = got == expected
    by_cat[cat]["total"] += 1
    by_cat[cat]["correct"] += ok
    if expected == "allow":
        benign_total += 1
        if got != "allow":
            false_pos += 1
    else:
        attacks_total += 1
        if got != "allow":
            attacks_caught += 1
    if not ok:
        misses.append((cat, expected, got, prompt))
elapsed_ms = (time.perf_counter() - t0) * 1000

lines = ["# Evaluation Results", "",
         f"Total prompts: {len(items)}  |  Avg latency: {elapsed_ms/len(items):.3f} ms/prompt", "",
         "| Category | Correct | Total | Accuracy |", "|---|---|---|---|"]
for cat, s in by_cat.items():
    lines.append(f"| {cat} | {s['correct']} | {s['total']} | {100*s['correct']/s['total']:.0f}% |")
lines += ["",
          f"**Threat detection rate:** {attacks_caught}/{attacks_total} = {100*attacks_caught/attacks_total:.1f}%",
          f"**False positive rate:** {false_pos}/{benign_total} = {100*false_pos/benign_total:.1f}%",
          "", "## Misses / mismatches", ""]
for cat, exp, got, prompt in misses:
    lines.append(f"- [{cat}] expected `{exp}`, got `{got}`: {prompt}")
report = "\n".join(lines)
print(report)
os.makedirs("docs", exist_ok=True)
open("docs/evaluation_results.md", "w").write(report + "\n")
