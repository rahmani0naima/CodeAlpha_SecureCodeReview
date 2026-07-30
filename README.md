# CodeAlpha_SecureCodeReview

**CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review**
Author: Naima Rahmani

A static application security testing (SAST) exercise: a deliberately
vulnerable Flask application (`app.py`) was audited with **Bandit** and
**Semgrep**, every finding was documented, and a fully remediated version
(`app_fixed.py`) was produced and re-scanned to confirm the fixes.

## Repository Structure

```
CodeAlpha_SecureCodeReview/
├── app.py                  # Intentionally vulnerable target application
├── app_fixed.py             # Remediated version — every finding fixed
├── SECURITY_REPORT.md       # Full findings, tool evidence, CWE mapping, and fixes
├── bandit_before.txt        # Raw Bandit scan output — before
├── bandit_after.txt         # Raw Bandit scan output — after
├── semgrep_before.json      # Raw Semgrep scan output — before
└── README.md
```

## What Was Reviewed

`app.py` is a small Flask app built specifically as a scan target. It
contains 12 well-known vulnerability classes:

1. Hardcoded secret key
2. Hardcoded database credentials
3. SQL injection
4. OS command injection (`os.system`)
5. OS command injection (`subprocess`, `shell=True`)
6. Use of `eval()` on user input
7. Insecure deserialization (`pickle`)
8. Weak password hashing (MD5)
9. Insecure randomness for a security token
10. SSRF + disabled TLS certificate verification
11. Reflected XSS
12. Path traversal
13. Debug mode enabled + bound to all interfaces

Full details — location, tool evidence, CWE reference, risk explanation,
and the exact fix applied — are in [`SECURITY_REPORT.md`](./SECURITY_REPORT.md).

## Results

| | Before | After |
|---|---|---|
| Bandit High | 5 | 0 |
| Bandit Medium | 5 | 0 |
| Bandit Low | 5 | 3 (justified residual — see report §4) |
| Semgrep findings | 27 | Remediated — see report §3 |

## Tools Used

- [Bandit](https://bandit.readthedocs.io/) v1.9.4 — Python-specific SAST
- [Semgrep](https://semgrep.dev/) — multi-language SAST, `auto` ruleset

## Running the Scans Yourself

```bash
pip install bandit semgrep

bandit app.py                                              # before
bandit app_fixed.py                                        # after

semgrep --config auto app.py --json -o semgrep_before.json
semgrep --config auto app_fixed.py --json -o semgrep_after.json
```

## Disclaimer

`app.py` contains real, exploitable vulnerabilities on purpose. It exists
only to be scanned and reviewed — **do not deploy it**, and do not reuse any
pattern from it in a real application. Use `app_fixed.py` as the reference
for the corrected approach to each issue.

---
*Part of the CodeAlpha Cyber Security Internship — Task 3: Secure Coding
Review.*
