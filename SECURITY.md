# Security

For responsible disclosure, do not open public issues containing exploitable information or secrets. Contact the repository maintainers through a private channel listed on their GitHub profile. If none is provided, request a private reporting channel before sharing sensitive details.

This reference implementation is designed for isolated local testing. Public deployment requires a separate threat model, secure TLS certificate lifecycle, access controls, secret management, vulnerability patching, and monitoring.

Never push `.env`, private keys, access tokens, or API credentials. Rotate immediately if accidentally exposed. Validate your changes with `scripts/validate.sh` before deployment.
