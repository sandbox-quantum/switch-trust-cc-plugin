---
description: Show Switch Trust ROI plugin status (resolved config, state dir, recent log lines)
---

Your plugin settings, as configured via `/config`:

- Switch Trust API Key: ${user_config.switch_trust_api_key}
- Switch Trust Ingestion Endpoint: ${user_config.switch_trust_environment}
- Report Mode: ${user_config.switch_trust_mode}

Run this command and show me its full output:

```
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/ccusage_reporter.py status --state-dir "${CLAUDE_PLUGIN_DATA}"
```

Then, in plain language:

- Never repeat or print the literal Switch Trust API Key value shown above, even
  if it doesn't look masked.
- Say whether the Switch Trust API Key appears to be configured, based on whether
  the settings block above shows a non-empty value for it.
- Say which report mode is active and, briefly, what that means for what
  gets sent (see the plugin's README "Report modes" section if you need the
  details).
- If the key doesn't appear to be set, tell the user to set it via `/config`
  (look for "Switch Trust API Key" under this plugin's settings). A project's
  `.claude/settings.json` / `.claude/settings.local.json` and a plain shell
  environment variable are not read for this — only `/config` has effect.
- If the `last_failure` line shows a failure, call it out first: a 401
  "invalid key" means the key needs fixing in `/config`, a `location_host`
  means the endpoint is being redirected, and "breaker OPEN" means reporting
  is paused until the time shown. Unsent turns are kept and retried.
