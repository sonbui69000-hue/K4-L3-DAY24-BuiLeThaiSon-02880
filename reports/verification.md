# Verification

## Test results

- Python: 3.14.6
- PII: `gold=118 pred=118 tp=118`, precision `1.000`, recall `1.000`
- Policy: 4 passed
- OBO: 5 passed
- Ledger: 3 passed
- Split: 1 passed
- Injection: 8 passed, 0 skipped
- Supply chain: 3 passed
- Full suite: 33 passed

## Supply chain

- Gitleaks: 8.30.1
- `gitleaks git --config .gitleaks.toml --redact .`: exit 1, 1 expected finding at `1bdd849`
- `gitleaks dir --config .gitleaks.toml --redact .`: exit 0, no findings
- Lock install: `pip install --require-hashes` passed in a temporary target
- `pre-commit run --all-files`: passed with pinned `gitleaks-system`

## CP5 proof

- `attack-before.log`: 4 lines, 1192 bytes
- `attack-after.log`: 0 lines, 0 bytes
- `reports/ledger.jsonl`: 46 lines
- `ledger.verify()`: `True`
- Final ledger entry: `http_post`, `deny`, reason present, `on_behalf_of=dpo`

## Limits and notes

Regex may miss unusual formatting, unlabelled bank numbers, or names and addresses. It does not replace a trained NER system.

Identity is mocked. The sink is localhost only. Hash chain checks in-file edits but not trusted rewrites or tail deletion.

No project virtual environment was present. Tests used Python 3.14 and a temporary dependency target.

Initial pip-tools resolution hit a cache permission error and restricted DNS. A temporary cache and PyPI index fixed it. Initial hook arguments caused a two-argument error. Removing custom arguments fixed the hook.
