# Security Policy

Thanks for helping keep Tidewall and its users safe.

## Supported Versions

While the project is in alpha (0.x), only the latest minor release
receives security fixes.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security findings.**

Instead, use one of:

- GitHub Security Advisories on this repository (`Security` tab →
  `Report a vulnerability`).
- Email: `security@tidewall.ai`.

Please include:

- A description of the issue and where it lives in the code.
- Steps to reproduce, ideally with a minimal proof-of-concept.
- The impact — what an attacker could do if exploited.
- Any mitigations or workarounds you've identified.

## What to Expect

- We aim to acknowledge new reports within **3 business days**.
- We'll work with you on a fix and a coordinated disclosure timeline.
- We're happy to credit you in the advisory once the fix is public,
  unless you'd prefer to remain anonymous.

## Particular Categories of Interest

- Authentication / authorization bypasses (API key, device token, RBAC).
- Detector evasion — prompts that bypass blockers when they shouldn't.
- Vault / unredact issues (PII leakage, FPE key handling).
- SQL injection or path traversal.
- Open redirects, SSRF, or insecure deserialization.

## Out of Scope

- Issues in third-party dependencies — please report upstream.
- Theoretical attacks requiring attacker control of the host environment.
- Findings that depend on misconfiguration the documentation explicitly
  warns against.

If in doubt, send the report anyway — we'll take a look.
