# Secrets incident

- Scanner: Gitleaks 8.30.1
- Historical scan: exit 1, 4 commits scanned, 1 finding
- Commit: `1bdd849`
- File and rule: `lab-fake-secret.txt`, `lab24-synthetic-token`
- Current tree scan: exit 0, no leaks found

Token is synthetic and invalid. It was not used as a credential.

If this were real, revoke and rotate it at the issuing service. Review use, remove copies, and clean exposed history.

Deleting a file from HEAD does not revoke a token. Dependency pinning improves repeatability but does not revoke secrets.
