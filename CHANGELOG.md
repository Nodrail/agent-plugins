# Changelog

## 0.9.2

- Rebuild both plugin hooks with the 0.9.2 client: local secret files are read through a checked file descriptor, receipt and Markdown parsing no longer backtrack, and telemetry writes its status atomically and refuses redirects.

## 0.9.1

- Rebuild both plugin hooks with the 0.9.1 client.
- Document the upgrade from the standalone plugin to a repository connection.
- Use the origin saved alongside a self-hosted credential for Codex and Claude Code.
