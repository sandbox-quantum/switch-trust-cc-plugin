# Changelog

All notable changes to this plugin are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the plugin uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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

### Fixed

- A single malformed transcript byte (a lone UTF-16 surrogate, e.g. from
  binary tool output) no longer permanently stalls a session's reporting
  cursor.
- Reporting progress now saves per turn instead of all-or-nothing, so a
  slow or failing ingestion endpoint no longer blocks every subsequent
  report for that session.
- `plugin.json`'s `version` and the wire protocol's `SENSOR_VERSION` can no
  longer drift independently -- a test now asserts they match.
