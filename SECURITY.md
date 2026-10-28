# Security policy

RepBridge is an experimental single-owner tool. There is no response-time or remediation SLA. Security fixes target the current
main branch and the latest published release. Older versions should be upgraded
rather than exposed to untrusted clients.

## Report privately

Use GitHub's **Security → Report a vulnerability** on the published repository.
The maintainer must enable private vulnerability reporting before publication.
If that button is unavailable, open an issue asking only for a private reporting
channel; do not include vulnerability details, account data or exploit secrets.
Do not invent an email address or contact an unrelated dependency maintainer for
RepBridge-specific issues.

Include affected version/image digest, transport, expected versus actual
behavior and an offline reproduction where possible. Redact credentials,
tickets, OTPs, browser cookies, tunnel runtime keys and Garmin account data.
Maintainers should acknowledge receipt, agree on a coordinated disclosure and
publish an advisory when appropriate. Timing is agreed per report.

## Scope and trust

- One Garmin account and one owner per deployment; this is not tenant isolation.
- Docker administrators and anyone with both key and token volumes are trusted.
- The server enforces policy; the MCP host enforces human approval for writes.
- Allowed Garmin data is disclosed to the assistant/model provider you select.
- Garmin sign-in uses Garmin's origin. Never send passwords or OTPs to the model.
- The HTTP bearer endpoint is private and bound to loopback. Public ingress
  needs HTTPS and an established authorization provider.
- The OpenAI tunnel is restricted to the intended owner/workspace.
- Unofficial Garmin endpoints can change without notice.

A successful build or encrypted storage is not a security certification.
Review the current dependency and image scans before publishing or upgrading.
