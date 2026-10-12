"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_PATTERNS = {
    "VN_CCCD": re.compile(r"(?<!\d)\d{12}(?!\d)"),
    "VN_PHONE": re.compile(r"(?<!\d)0(?:[\s.-]?\d){9,10}(?!\d)"),
    "VN_BANK_ACCOUNT": re.compile(
        r"(?i)\b(?:STK|số\s+tài\s+khoản)\s*[:#-]?\s*(\d{8,16})(?!\d)"
    ),
    "EMAIL": re.compile(
        r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
    ),
}

_PRIORITY = {
    "VN_BANK_ACCOUNT": 0,
    "VN_CCCD": 1,
    "VN_PHONE": 2,
    "EMAIL": 3,
}


def _candidates(text: str) -> list[dict]:
    found: list[dict] = []
    for kind, pattern in _PATTERNS.items():
        for match in pattern.finditer(text):
            start, end = match.span(1) if kind == "VN_BANK_ACCOUNT" else match.span()
            found.append({"type": kind, "start": start, "end": end})
    return found


def detect(text: str) -> list[dict]:
    selected: list[dict] = []
    candidates = sorted(
        _candidates(text),
        key=lambda item: (
            item["start"],
            -(item["end"] - item["start"]),
            _PRIORITY[item["type"]],
        ),
    )
    for candidate in candidates:
        if not any(
            candidate["start"] < item["end"]
            and item["start"] < candidate["end"]
            for item in selected
        ):
            selected.append(candidate)
    return sorted(selected, key=lambda item: (item["start"], item["end"]))


def redact(text: str) -> str:
    result = text
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        result = result[: entity["start"]] + replacement + result[entity["end"] :]
    return result
