# Compliance mapping

| Source or topic | Control used | Evidence file:line | Limit |
|---|---|---|---|
| [Luật 91/2025/QH15](https://vanban.chinhphu.vn/?classid=1&docid=214590&pageid=27160&typegroup=) | Detect and redact synthetic CCCD, phone, bank account, and email data. | `agent/pii.py:36-89`; `agent/runner.py:145-147` | Specific articles not verified. This lab does not prove legal compliance. |
| [NĐ 356/2025/NĐ-CP](https://vanban.chinhphu.vn/?classid=1&docid=216387&pageid=27160) | Enforce principal, purpose, scope, expiry, and restricted egress rules. | `agent/policy.py:78-101`; `data/principals.json:2-3` | Specific articles not verified. Principals are mock fixtures. |
| [Luật AI 134/2025/QH15](https://vanban.chinhphu.vn/?classid=1&docid=216334&orggroupid=1&pageid=27160) | Separate untrusted ticket text from customer reads. Record tool decisions in a hash chain. | `agent/runner.py:90-197`; `agent/ledger.py:45-85` | Specific articles not verified. This is not an AI governance assessment. |
| [OWASP ASI01, ASI03, ASI04](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | ASI01: injection lures and split containment. ASI03: OBO scope checks. ASI04: pinned hook, lock hashes, and history scan. | `injection-corpus.md:47-116`; `tests/test_obo.py:29-72`; `.pre-commit-config.yaml:1-6`; `requirements.lock:1-10`; `reports/secrets-incident.md:3-13` | OWASP mapping is educational. It is not a certification or a complete threat review. |

Law article numbers were not verified from source text. Technical evidence does not prove compliance.
