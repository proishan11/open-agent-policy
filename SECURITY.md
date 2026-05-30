# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| v0.x (current) | ✅ |

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

If you discover a security vulnerability in Open Agent Policy, please report it responsibly:

1. **Email:** security@oap.dev
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix timeline:** depends on severity, targeting 30 days for critical issues

## Scope

The following are in scope:

- OAP server (`oap-server`)
- OAP CLI (`oapctl`)
- OAP SDKs (Python, TypeScript)
- OAP gateway and MCP proxy
- Policy evaluation logic
- Grant/token issuance
- Audit event integrity

The following are out of scope:

- Vulnerabilities in third-party dependencies (report to the upstream project)
- Social engineering attacks
- Denial of service without a clear exploit

## Security practices

OAP follows these security practices:

- **Secret scanning:** Gitleaks in pre-commit hooks and CI
- **Dependency scanning:** Dependabot for automated updates
- **SAST:** CodeQL in CI for semantic security analysis
- **Container scanning:** Trivy for container images
- **Signed releases:** All release artifacts are signed
- **SBOM:** Software Bill of Materials published with each release

## Disclosure policy

We follow coordinated disclosure. We will:

1. Confirm the vulnerability
2. Develop and test a fix
3. Release the fix
4. Publish a security advisory with credit to the reporter
