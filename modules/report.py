"""
Reporting engine.

Turns simulation results into a Markdown audit report comparing the original
mock payload against each transformed variant, along with the evasion
success rate and defensive recommendations.
"""

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

RECOMMENDATIONS: List[str] = [
    "**Move beyond static signatures.** Signature matching on plaintext is trivially defeated by encoding, splitting, or inserting noise. Treat signatures as one layer, not the primary control.",
    "**Normalize before scanning.** Decode, decompress, and de-obfuscate content (including string concatenation and encoding layers) before running signature checks.",
    "**Adopt behavioral detection.** Monitor what a process or script *does*: process ancestry, unusual child processes, suspicious API or command sequences, and unexpected network or file activity.",
    "**Use semantic and heuristic analysis.** Score intent and structure rather than exact strings. Entropy analysis, AST-level inspection, and emulation can flag transformed content that exact matching misses.",
    "**Collect rich telemetry.** Enable script block logging, command-line auditing, and EDR event collection so that suspicious activity is visible even when the artifact itself is obfuscated.",
    "**Correlate across events.** A single weak signal rarely matters. Correlate low-fidelity events over time and across hosts to surface attack chains.",
    "**Test continuously.** Run purple-team exercises and regression tests against your own detections, and measure detection coverage instead of assuming it.",
]


def compute_evasion_rate(results: List[Dict]) -> float:
    """Percentage of transformed variants that bypassed the static blacklist."""
    if not results:
        return 0.0
    bypassed = sum(1 for r in results if not r["scan"]["detected"])
    return bypassed / len(results) * 100.0


def _fence_for(text: str) -> str:
    """Pick a backtick fence longer than any backtick run inside the text."""
    runs = re.findall(r"`+", text)
    longest = max((len(run) for run in runs), default=0)
    return "`" * max(3, longest + 1)


def _code_block(text: str) -> str:
    fence = _fence_for(text)
    return f"{fence}text\n{text}\n{fence}"


def _matches_label(scan: Dict) -> str:
    return ", ".join(scan["matches"]) if scan["matches"] else "None"


def build_report(
    payload: str,
    original_scan: Dict,
    results: List[Dict],
    generated_at: Optional[datetime] = None,
) -> str:
    """
    Build a Markdown audit report.

    `results` is a list of dicts with keys:
        name, output, roundtrip (bool), scan (scanner.scan() result)
    """
    timestamp = (generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    total = len(results)
    bypassed = sum(1 for r in results if not r["scan"]["detected"])
    rate = compute_evasion_rate(results)

    lines: List[str] = []
    lines.append("# Payload Obfuscation & Detection Evasion Audit Report")
    lines.append("")
    lines.append(f"**Generated:** {timestamp}")
    lines.append("")
    lines.append(
        "> Educational simulation. All payloads are benign mock strings. "
        "The scanner is a naive static signature matcher used for teaching purposes."
    )
    lines.append("")

    # 1. Original payload
    lines.append("## 1. Original Payload")
    lines.append("")
    lines.append(_code_block(payload))
    lines.append("")
    lines.append(f"**Static scan result:** {original_scan['status']}")
    lines.append("")
    lines.append(f"**Matched signatures:** {_matches_label(original_scan)}")
    lines.append("")

    # 2. Comparison table
    lines.append("## 2. Transformation Comparison")
    lines.append("")
    lines.append("| Technique | Static Scan Result | Matched Signatures | Round-trip Verified |")
    lines.append("|---|---|---|---|")
    for r in results:
        lines.append(
            f"| {r['name']} | {r['scan']['status']} | {_matches_label(r['scan'])} | "
            f"{'Yes' if r['roundtrip'] else 'No'} |"
        )
    lines.append("")

    # 3. Obfuscated payloads
    lines.append("## 3. Obfuscated Payloads")
    lines.append("")
    for r in results:
        lines.append(f"### {r['name']}")
        lines.append("")
        lines.append(_code_block(r["output"]))
        lines.append("")
        lines.append(f"Static scan: **{r['scan']['status']}**")
        lines.append("")

    # 4. Evasion success rate
    lines.append("## 4. Evasion Success Rate")
    lines.append("")
    lines.append(
        f"**{rate:.1f}%** of transformed variants ({bypassed} of {total}) "
        "bypassed the static blacklist."
    )
    lines.append("")
    if original_scan["detected"] and total:
        lines.append(
            "The original payload was detected in plaintext, so the drop in detection "
            "across variants reflects the weakness of exact-match signatures rather than "
            "any change in the underlying content."
        )
    else:
        lines.append(
            "The original payload was not detected in plaintext, so this simulation does "
            "not demonstrate evasion. Add a blacklisted term to the payload to observe the effect."
        )
    lines.append("")

    # 5. Analysis
    lines.append("## 5. Analysis: Why Static Detection Fails")
    lines.append("")
    lines.append(
        "Static signature matching assumes the attacker's content will appear in "
        "plaintext in a predictable form. Encoding changes the bytes, string splitting "
        "removes contiguous keywords, and noise insertion breaks up signatures, while the "
        "meaning of the content is preserved for anyone or anything that knows how to decode it."
    )
    lines.append("")

    # 6. Recommendations
    lines.append("## 6. Recommendations: Upgrading to Behavioral Detection")
    lines.append("")
    for rec in RECOMMENDATIONS:
        lines.append(f"- {rec}")
    lines.append("")

    return "\n".join(lines) + "\n"
