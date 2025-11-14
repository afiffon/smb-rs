---
name: Bug report
about: Create a report to help us improve
title: 'Bug: '
labels: bug
assignees: afiffon

---

## Describe the bug

A clear and concise description of what the bug is.

## To Reproduce

Contain a code snippet that uses the crate, and reproduces the bug.

## Environment details

- If this is a runtime failure, please provide:
  - SMB server software and version (e.g. Samba 4.15.0 or Windows Server 2022)
  - Authentication method, if relevant (ntlm/kerberos - domain environment?)
  - Custom configuration or used features, if relevant

- Crate version: [e.g. 0.8.1]
- OS, architecture & version: [e.g. macOS 15.2, arm64]

## Logs

Please provide a detailed log of the issue.

Preferably, run with `RUST_LOG=DEBUG`.

*Do not share any sensitive information:*

- Trim the log to the relevant parts.
- Remove authentication details (usernames, passwords, hashes, etc).
- Remove logs regarding Session Setup and `sspi` if the problem doesn't relate to authentication.
