# Security Policy

## Supported Versions

Currently, as we are in the `1.0.0-beta` phase, only the latest release on the `main` branch is actively supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| v1.0.x  | :white_check_mark: |
| < v1.0  | :x:                |

## Reporting a Vulnerability

**ProvnZero** fundamentally relies on cryptographic and systemic memory-safety guarantees (Zero Data Retention). Finding flaws in this model is something we take extremely seriously.

**Please do not report security vulnerabilities through public GitHub issues.** 

Instead, please report them directly via email to the maintainers (e.g. `contact@provnai.com` or the author's primary contact).

If you submit a valid vulnerability report:
- We will acknowledge receipt of your vulnerability report as soon as possible.
- We will prioritize addressing the vulnerability above all other feature development.
- We ask that you adhere to responsible disclosure guidelines, providing us 90 days to issue a fix or mitigation before publishing details.

### What is considered a vulnerability?
- Memory/data leaks where plaintext prompt data survives the termination of the `SecureBuffer` lifecycle.
- Cryptographic flaws in the HPKE sealing or unsealing implementation.
- Exploitable panics (`unwrap()` failures triggers via remote payload).
- Authentication bypass on VEX receipt signatures.
