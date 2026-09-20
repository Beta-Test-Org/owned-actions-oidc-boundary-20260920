# Researcher-owned GitHub Actions identity-boundary lab

This temporary public repository is an authorized security test fixture owned by
the researcher. It contains no production secret and has no trust relationship
with any cloud provider.

The workflows request short-lived GitHub OIDC tokens for the synthetic audience
`urn:owned-actions-lab:github-oidc-boundary`, decode them in memory, and print
only selected non-secret claims. Raw JWTs and OIDC request credentials are never
logged or uploaded.

Scope is limited to this repository, its researcher-owned fork, GitHub-hosted
runners, and reversible test objects.
