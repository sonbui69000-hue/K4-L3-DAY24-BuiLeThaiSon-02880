# DPIA-lite

1. Data: synthetic tickets and synthetic customer records. Sensitive fields include CCCD, phone, bank account, and email. Ticket data is internal. Customer records are restricted.

2. Purpose and principals: `support_l1` may search tickets. `dpo` may read a customer record for `support-reply`. Principal data is a mock fixture, not authentication.

3. Data path: Run A calls `search_docs`, redacts text, and extracts ticket IDs from filenames. Run B maps IDs through `related_tickets`, checks policy, reads allowed records, and writes ledger entries. Egress targets only the localhost sink.

4. Decisions and limits: `support_l1` cannot read customer records. `dpo` can read valid records. Restricted egress is denied. Full tests passed. `attack-before.log` has synthetic leakage. `attack-after.log` is 0 bytes. Limits include mock identity, regex PII detection, local sink, and a hash chain that does not detect trusted rewrite or tail deletion.
