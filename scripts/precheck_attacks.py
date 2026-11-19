#!/usr/bin/env python3
"""
Pre-check (offline, KHÔNG gọi API) cho prompt tấn công CP4.

Chạy từ gốc repo:
    python scripts/precheck_attacks.py

Với mỗi prompt trong ``src/attacks/attacks.py::adversarial_prompts``, cho biết:
  - còn để "TODO" không / độ dài
  - Red Advance L1 regex: injection pattern nào khớp, topic filter có chặn không
  - Red Advance L2 (phần không cần LLM): prompt có chứa giá trị protected không
Lớp self-check LLM (L2/L4) không thể kiểm tra offline — chỉ biết khi chạy --part 4.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agents.guards_agent import _INJECTION_PATTERNS, topic_filter_strong  # noqa: E402
from agents.red_advance_nemo import mentions_protected_value  # noqa: E402
from agents.security_boundary import (  # noqa: E402
    INSTRUCTION_OVERRIDE_PATTERNS,
    normalize_for_security,
)
from attacks.attacks import adversarial_prompts  # noqa: E402
from core.config import ALLOWED_TOPICS, BLOCKED_TOPICS  # noqa: E402


def matched_injection_patterns(text: str) -> list[str]:
    norm = normalize_for_security(text)
    hits = []
    for p in list(INSTRUCTION_OVERRIDE_PATTERNS) + list(_INJECTION_PATTERNS):
        m = re.search(p, norm, re.IGNORECASE)
        if m:
            hits.append(f"{m.group(0)!r}  ← /{p}/")
    return hits


def main() -> int:
    print(f"{len(adversarial_prompts)} prompt(s)\n")
    reach_llm = 0
    for a in adversarial_prompts:
        text = a.get("input", "")
        lower = text.lower()
        print(f"#{a['id']} [{a['category']}]  ({len(text)} ký tự)")
        if "TODO" in text:
            print("   ✗ Còn TODO — chưa viết prompt\n")
            continue

        problems = []
        inj = matched_injection_patterns(text)
        if inj:
            problems.append("L1 injection regex khớp:")
            problems.extend(f"      {h}" for h in inj)
        if topic_filter_strong(text):
            bad = [b for b in BLOCKED_TOPICS if b in lower]
            if bad:
                problems.append(f"L1 topic: chứa từ cấm {bad}")
            else:
                problems.append("L1 topic: không có từ khoá banking nào "
                                f"(cần 1 trong {ALLOWED_TOPICS[:8]}…)")
        if mentions_protected_value(text):
            problems.append("L2 protected value check: prompt chứa giá trị secret")

        if problems:
            print("   ✗ Red Advance sẽ chặn trước khi tới LLM:")
            for p in problems:
                print(f"     - {p}" if not p.startswith("      ") else p)
        else:
            reach_llm += 1
            print("   ✓ Qua L1 regex + phần offline của L2 "
                  "(còn NeMo self-check input/output — chỉ biết khi chạy thật)")
        if len(text) < 150:
            print("   ! Prompt ngắn — CHECKPOINTS khuyên prompt dài, cụ thể")
        print()

    print(f"Tới được NeMo self-check: {reach_llm}/{len(adversarial_prompts)}")
    print("Lưu ý: Red (default) không có guardrail — prompt bị chặn ở đây vẫn có thể leak Red.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
