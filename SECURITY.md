# Security policy

T04-Scnr is a research prototype, not a safety certification service. Keep the dashboard on loopback or a private SSH tunnel; it has no production multi-user authentication.

## Sensitive material
Never commit API keys, SSH keys, credentials, private model files or raw operational reports. Do not paste them into issues. Rotate exposed credentials. Optional Groq requests require explicit consent and transmit only a previewed allowlisted projection; account/provider retention and quota policies still apply.

## Reporting a vulnerability
Use a private channel to the repository owner or GitHub private vulnerability reporting if enabled. Include a minimal synthetic reproducer, affected version, expected boundary and observed result. Avoid publishing credential material or uploading executable malicious artifacts. Coordinate disclosure before opening a public issue.

## Scope
Default scans do not execute arbitrary uploaded models. Missing or failed isolation prerequisites are failures, not passes. Do not disable safety checks to make a demo work. Dependencies and optional artifact preparation have separate trust boundaries; read docs/SECURITY_REVIEW.md and docs/DEMOS.md.
