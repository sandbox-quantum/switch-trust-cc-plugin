# Security Policy

## Supported Versions

Security fixes are applied to the latest released version only. There is no
backport or long-term-support branch -- enable auto-update for this
marketplace (see README) so fixes reach you automatically.

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |
| < latest | ❌       |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub
issues, discussions, or pull requests.

Instead, report them privately using GitHub's
[private vulnerability reporting](https://github.com/sandbox-quantum/switch-trust-cc-plugin/security/advisories/new)
feature (the "Report a vulnerability" button under the repository's
**Security** tab).

When reporting, please include as much of the following as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof of concept
- Affected version(s)
- Any suggested remediation

We will acknowledge receipt of your report and work with you on a
coordinated disclosure. Please give us a reasonable amount of time to
address the issue before any public disclosure.

## Scope

This policy covers the `switch-trust-cc-plugin` package in this repository.

The plugin runs locally inside Claude Code, on every `Stop` and
`SessionEnd`, and reports usage data to a fixed ingestion endpoint. Its
security-relevant surface is:

- **Credential handling.** The Switch Trust API key is read only from the
  `CLAUDE_PLUGIN_OPTION_SWITCH_TRUST_API_KEY` environment variable Claude
  Code injects per hook invocation (never from a project's own
  `.claude/settings.json` or a bare `os.environ` match of the same name,
  which could otherwise let a committed project file hijack it). It is sent
  only in the request's `Authorization: ApiKey ...` header, is never
  written to the on-disk log or state files, and is never printed -- only a
  one-way SHA-256 hash of `endpoint + api_key` is kept, to key local
  circuit-breaker/retry state.
- **Endpoint allowlisting.** The ingestion endpoint must be `https://` on an
  allowlisted `switchagents.ai` host, or `http://localhost` /
  `http://127.0.0.1` for local development -- anything else is refused
  before the key is ever attached to a request.
- **No redirect following.** The HTTP client refuses to follow 3xx
  redirects, so the `Authorization` header can never be replayed to a
  different (or downgraded) host by a malicious or misconfigured server.
- **Local state.** State and the debug log live under
  `${CLAUDE_PLUGIN_DATA}` (or `~/.switch-trust/roi_cc_plugin/` as a
  fallback), created `0700`/`0600` -- not world-readable, despite holding
  email, session IDs and error response bodies.
- **Redaction is best-effort, not a guarantee.** In `text`/`full` Report
  Modes, pattern-based redaction strips recognizable secrets (cloud/API
  keys, PEM blocks, JWTs, `password=`-style assignments) before anything is
  sent, but it cannot catch everything -- see the README's Data & Privacy
  section. If your repository or shell output may contain regulated data,
  use `condensed` or `none` instead of relying on redaction.
- **A repository can only lower what it sends.** A project's own committed
  settings can reduce the Report Mode but cannot raise it, change the API
  key, the endpoint, or the user-email override.

Reports related to any of the above are especially welcome, as are reports
about dependency vulnerabilities (this plugin has none at runtime -- pure
Python 3 standard library).

## Release integrity

This repository's `main` branch and `v*` release tags are protected by
repository rulesets: pushes require an approved, code-owner-reviewed pull
request with no stale or force-pushed approvals, and tag creation is
limited to the release owners team (see
[CODEOWNERS](.github/CODEOWNERS)). `plugin.json`'s `version` and the
sensor's wire-protocol `SENSOR_VERSION` are asserted to match in CI, so the
version a release tag names is the version every subsequent report
actually declares itself as.
