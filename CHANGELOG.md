# Changelog

All notable changes to this plugin are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the plugin uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-12

### Changed (breaking)

- Renamed the plugin, its userConfig keys, environment variables and local
  state directory from Flint/FlintAI (`flintai-cc-plugin`, `flintai_*`,
  `FLINTAI_*`, `~/.flintai/`) to Switch Trust (`switch-trust-cc-plugin`,
  `switch_trust_*`, `SWITCH_TRUST_*`, `~/.switch-trust/`). There is no
  migration: existing installs keep reporting under the old identifiers
  until a user re-saves their settings under the new keys.

### Security

- Redact recognizable secrets (cloud and API keys, private keys, JWTs,
  `Authorization` headers, credentials in URLs, `password=`-style
  assignments) from `text`/`full` mode reports before they are sent, and
  cap prompt/response/tool block and event sizes. `condensed` remains the
  safest mode -- see the README's Data & Privacy section.
- Stop following HTTP redirects when posting events -- a redirect could
  otherwise have the `Authorization: ApiKey ...` header replayed to a
  different, possibly downgraded, host.
- Create plugin state directories and files `0700`/`0600` instead of
  world-readable -- they hold email, session IDs, and ingestion error
  response bodies.
- Resolve the API key, ingestion endpoint, report mode and user-email
  override only from Claude Code's saved `/config` values -- never from a
  project's `.claude/settings.json`/`settings.local.json`, which could
  otherwise redirect a user's key and conversation data to another tenant.
  A project's settings can only make the report mode less detailed, never
  more.
- Enforce an ingestion-endpoint allowlist (an allowlisted host over
  `https://`, or `http://localhost`/`http://127.0.0.1` for local
  development) before every request. Stop using the user's `gcloud`
  credentials to resolve their email -- identity now resolves entirely
  locally (`git config user.email`, then the OS login name).
- Redact the `condensed`-mode session title, repo name and branch the same
  way `text`/`full` prompts are redacted, so a secret pasted into the
  session title no longer reaches ingestion unredacted.
- Redact structured personal data -- payment cards, US SSNs, IBANs, and
  keyword-labelled passport/driver's-licence/MRN/date-of-birth values --
  from prompts, responses, tool input/output and the `condensed` title
  before upload, in every report mode. Controlled by the new
  `switch_trust_pii_redaction` option (`default`/`strict`/`off`); a
  project's settings can only raise it, never lower it below `default`.

### Fixed

- A single malformed transcript byte (a lone UTF-16 surrogate, e.g. from
  binary tool output) no longer permanently stalls a session's reporting
  cursor.
- Reporting progress now saves per turn instead of all-or-nothing, so a
  slow or failing ingestion endpoint no longer blocks every subsequent
  report for that session.
- `plugin.json`'s `version` and the wire protocol's `SENSOR_VERSION` can no
  longer drift independently -- a test now asserts they match.
