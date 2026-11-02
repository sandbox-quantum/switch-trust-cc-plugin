# switch-trust-cc-plugin — Claude Code usage & cost reporter

**See what Claude Code is actually costing you.**

A Claude Code plugin that reports your usage — tokens, model, and computed
cost — to the Switch Trust platform, so your Switch Trust cost/ROI dashboards reflect
real Claude Code consumption, per user and per repo, over time. Once installed,
it runs quietly in the background; no dependencies to install, nothing to run
day-to-day.

## Install

```
/plugin marketplace add https://github.com/sandbox-quantum/switch-trust-cc-plugin
/plugin install switch-trust-cc-plugin@switch-trust-cc-plugins
```

Claude Code will prompt you for the settings below — enter at least your
Switch Trust API Key. You can revisit these any time via `/config`; your key is
stored in your OS's secure credential store, never in plaintext. These
settings come from `/config` only — a repository you open can only lower the
Report Mode or make PII Redaction stricter (never the reverse, or change your
key, endpoint or identity).

| Setting | Required | Description |
| --- | --- | --- |
| Switch Trust API Key | yes | Your Switch Trust API key (`sk_...`) |
| Switch Trust Ingestion Endpoint | no | URL of the ingestion service (defaults to production instance). Must be `https://` on an allowed Switch Trust host, or `http://localhost` / `http://127.0.0.1` for local development — anything else is refused and logged, never sent. |
| User Email Override | no | Override the per-user identity used for attribution (else auto-detected locally: `git config user.email` → OS login name; no cloud credentials are used — see [Data & Privacy](#data--privacy)) |
| Report Mode | no | `condensed`, `text`, `full` (default), or `none` (disables reporting) — see [Report modes](#report-modes) |
| PII Redaction | no | `default` (default), `strict`, or `off` — best-effort replacement of email and IP addresses, card numbers, national ID numbers, IBANs and labelled IDs; see [PII redaction](#pii-redaction) |

- Hooks and the `/switch-trust-status` command activate as soon as the install
  finishes. If the install summary asks you to, run `/reload-plugins` (a full
  restart is not required).
- No dependency install step needed — the plugin is pure Python 3 standard
  library.

To opt out entirely without uninstalling, set Report Mode to `none` via
`/config`.

## Keeping it updated

Claude Code pins the version you installed — you won't get security or bug
fixes until you update. Third-party marketplaces have auto-update **off** by
default, so turn it on:

```
/plugin
```

Open the **Marketplaces** tab, select `switch-trust-cc-plugins`, and choose
**Enable auto-update**. From the shell instead:

```
claude plugin marketplace update switch-trust-cc-plugins --auto-update
```

**Org admins:** force it for everyone via [managed
settings](https://code.claude.com/docs/en/plugins/org.md):

```json
{
  "extraKnownMarketplaces": {
    "switch-trust-cc-plugins": {
      "source": {
        "source": "github",
        "repo": "sandbox-quantum/switch-trust-cc-plugin"
      },
      "autoUpdate": true
    }
  }
}
```

Once set there, users can't turn auto-update off with `/plugin`.

## Support

Questions or issues: open a
[GitHub issue](https://github.com/sandbox-quantum/switch-trust-cc-plugin/issues)
or email [support@switchagents.ai](mailto:support@switchagents.ai).

## Report modes

The **Report Mode** setting controls how much conversation detail is sent.

| Mode | What's collected |
| --- | --- |
| `full` (default) | Real prompts and responses, plus tool calls and tool results (commands run, file contents, tool output). |
| `text` | Real prompts and responses. No tool calls or results. |
| `condensed` | Token counts and a one-line AI-generated session summary only. No real conversation content. |
| `none` | Nothing — reporting is fully disabled. |

See [Data & Privacy](#data--privacy) below for exactly what each mode sends
and why `full` is the default.

## PII redaction

Before anything is sent, the plugin also replaces structured personal data on
your machine, in every mode (including the `condensed` title, repo and branch
string). This is pattern-based and **best-effort**: it reduces exposure, it
does not guarantee removal. The **PII Redaction** setting
(`switch_trust_pii_redaction`, set via `/config`) chooses what is replaced:

| Setting | What's replaced |
| --- | --- |
| `default` | **Email addresses**, together with the display name in `Name <address>` forms such as git `Author:` lines, `Co-authored-by:` trailers and package `author` fields. **IP addresses**, IPv4 and IPv6 (including compressed and IPv4-mapped forms), public and private alike: Legal treats an IP address as personal data, and a private address (`10.x`, `172.16–31.x`, `192.168.x`, `100.64.x`, link-local, `fc00::/7`) can still identify a person's machine. **Payment card numbers** with a known issuer prefix (Visa, Mastercard, Amex, Discover) and a valid Luhn check digit — in prose, CSV, SQL and JSON, including JSON numbers. **National ID numbers** that pass their check-digit or structure rules: US Social Security numbers in `123-45-6789` form that pass the SSA validity rules; UK National Insurance numbers (`AB123456C`, `AB 12 34 56 C`, `AB-12-34-56-C`, `AB 123456 C`), Spanish DNI/NIE numbers and Italian codici fiscali wherever they appear in upper case; Indian PANs in upper case, which have no public checksum and are matched by shape and their fourth-letter holder-type code only; French NIR, Indian Aadhaar and Belgian national numbers in their usual grouped forms (`1 84 12 76 451 089 46`, `2341 2341 2346`, `85.07.30-033.28`); and Canadian SINs, Dutch BSNs, Polish PESELs, 9-digit SSNs, lower-case NINO, PAN and DNI/NIE values, dashed Aadhaar numbers, and the ungrouped NIR, Aadhaar and Belgian forms only right after a label such as `SIN`, `BSN`, `PESEL`, `SSN`, `NINO`, `NI number`, `PAN`, `DNI`, `NIE`, `Aadhaar`, `NIR` or `rijksregisternummer`, or under a matching JSON key. **IBANs** with a valid checksum. **Passport, driver's licence and medical-record numbers, and dates of birth**, only right after a label such as `passport no.`, `driver's license`, `MRN`, `DOB` or `date of birth`, or under a matching JSON key in tool input. |
| `strict` | Everything in `default`, plus phone numbers in `+<country code><number>` form and phone numbers right after a label such as `phone`, `mobile` or `fax`. |
| `off` | Nothing. Secret redaction still applies. |

There is no separate switch for email or IP addresses: `off` turns off all
PII redaction, and secret redaction still applies.

These are never replaced, because they identify infrastructure rather than
a person, or because replacing them would garble ordinary developer
output: loopback and unspecified addresses (`127.0.0.1`, `::1`, `0.0.0.0`),
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`), multicast and reserved ranges, well-known public DNS
resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9` and their IPv6 equivalents),
cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, the ECS and
EKS agent addresses, Azure's `168.63.129.16`, Alibaba's
`100.100.100.200`), macOS's loopback-interface `fe80::1`,
network ranges written as CIDR `/24` or wider, four-part version strings
that follow a cue such as `version`, `v`, `==` or `Chrome/`, or appear in
a file name or URL path, `git@host:` remotes, `@example.com` and `.test`
addresses, `name@2x.png` file names, `package@version` specifiers, and SSH
algorithm names such as `…@openssh.com`.

Each value is replaced with a numbered placeholder such as `[card-1]`,
`[email-1]`, `[ip-2]` or `[nino-1]`. Within one report (everything one hook
run sends) the same value gets the same placeholder and different values get
different ones, so repeated tool calls can still be told apart. Placeholders
are plain sequence numbers, not hashes, so they cannot be reversed; numbering
restarts with each report.

Your own identity in the `agent` field (see [Data & Privacy](#data--privacy))
is attribution, not conversation content, and is sent unchanged.

It does **not** detect: names outside `Name <address>` forms, postal
addresses, phone numbers (outside `strict`), national ID numbers from other
countries, IDs that need a label when none is next to them, dates of birth
with no label next to them, IP addresses written in other notations (a
single integer, hex, or embedded in a host name such as
`ec2-54-12-88-3.compute.amazonaws.com`), or values split up or obfuscated.
EU national IDs are covered only where a reliable checksum exists, so, for
example, German, Swedish, Danish, Finnish and Portuguese numbers are not
detected. **Free-text special-category data — health conditions, religion,
political opinions, ethnicity, sexual orientation — is not detected at
all**; patterns cannot recognize it reliably.

It also replaces some look-alikes:

- well-known test card numbers, about 2–3% of random 16-digit order
  numbers, and card-like digit runs inside mostly-numeric hex IDs (an
  instance ID such as `i-4743355369860f07b` can become `i-[card-1]f07b`);
- most values shaped like `123-45-6789` (such as part numbers), unless a
  label such as `order id` or `part` sits right before them;
- about 38% of random upper-case `ABCDE1234F`-shaped codes (anything with
  a valid PAN holder-type letter in fourth place) and about 9% of random
  `AB123456C`-shaped codes (NINO rules), unless a label such as `part`,
  `sku`, `model` or `order id` sits right before them;
- about 8% of random space-grouped 12-digit numbers (`1234 5678 9012`, the
  Aadhaar check) and about 4% of 8-digit-plus-letter codes (`12345678Z`,
  the Spanish check letter);
- public-range dotted numbers that are not addresses, such as
  specification section numbers (`22.1.5.1`) and versions with no cue;
- the addresses of bots and role accounts (`noreply@…`, service accounts),
  which are replaced like anyone else's.

A repository you open can make this setting stricter, but never lower it or
turn it off.

## Data & Privacy

This is usage reporting, not anonymous telemetry — it is attributed to you
and your repository, and it runs on every `Stop` and `SessionEnd`. In every
mode except `none`, each report sent to the ingestion endpoint (default
`https://ingestion.switchagents.ai`, always a `switchagents.ai` subdomain) includes
your identity (email), your repository's name and a one-way hash of its git
origin URL (used to group usage by repo without storing the URL itself), the
Claude Code session ID, timestamps, the model name, and token counts.

`condensed` additionally includes the current git branch and an
AI-generated one-line session title, combined into a single summary string —
no real conversation text.

`text` and `full` additionally include the real prompt and response text for
each turn. `full` also includes tool calls and tool results — commands run,
file contents, and other tool output — as they appear in the transcript,
including any third-party data that happens to be in them. Redaction of
recognizable secrets and of structured personal data (see
[PII redaction](#pii-redaction)) is best-effort — it reduces exposure, it
does not guarantee removal.

**`full` is the default mode, and it sends real conversation content** — prompts,
responses, and tool inputs/outputs such as shell commands and file contents.
Switch Trust's ROI recommendations are built from that content, which is why
`full` is the default. If your organization's data-handling policies require
sending less, switch the **Report Mode** setting via `/config` — see [Report
modes](#report-modes) above for what each mode sends.

**Who can see it:** reports are visible to every member of your Switch Trust
organization, whatever their role. Your prompts, responses and (in `full`
mode) tool output can be read by your colleagues there.

**To turn this off:** set Report Mode to `none` via `/config`, or uninstall
the plugin. There is no per-session consent prompt — the setting applies to
every session until you change it.

Exactly what each field contains, by mode:

| Field | `full` (default) | `text` | `condensed` | `none` |
| --- | --- | --- | --- | --- |
| `session_id` | Claude Code session id | same | same | not sent |
| `agent` | `Claude Code — <your email>` (per-user attribution) | same | same | not sent |
| `model` | `message.model` from the transcript (e.g. `claude-opus-4-8`) | same | same | not sent |
| `input_tokens` | effective tokens for that turn | same as `full` | effective tokens for the whole session, folded to reflect real billing (cache reads/writes priced in) | not sent |
| `output_tokens` | output tokens for that turn | same as `full` | summed output tokens for the whole session | not sent |
| `prompt` | the real user message text for that turn, plus any tool results fed back to the model (command output, file contents) | the real user message text for that turn | `<ai-title> (<repo>:<gitBranch>)` — no real conversation text | not sent |
| `response` | the real assistant message text for that turn, plus any tool calls the assistant made (commands run, files edited) | the real assistant message text for that turn | never sent (left empty) | not sent |
| `app_info` | repository name, and a one-way SHA-256 hash of its git origin URL (sent as `slotid`) | same | same | not sent |
| `timestamp` | time of that turn | same as `full` | last message time in the reported window | not sent |

**Identity (`agent`'s `<your email>`):** resolved entirely locally, in order
— the **User Email Override** `/config` setting, then `git config
user.email`, then your OS login name, then left anonymous if none resolve.
No cloud provider or identity service (gcloud, AWS, etc.) is ever contacted
to look this up.

**Prohibited Data:** our terms of service prohibit sending protected health
information, payment-card data, government ID numbers, or other
special-category personal data through this plugin. In `full` mode (the
default), the plugin forwards whatever text appears in the files and command
output it is shown, filtered only by best-effort, pattern-based redaction of
secrets and of the structured personal data listed in
[PII redaction](#pii-redaction). Free-text health or other special-category
data is not detected. If your repository or shell output may contain any of
this data, use `condensed` or `text` mode, or `none`.

**More:** [Privacy Policy](https://docs.switchagents.ai/legal/privacy-policy),
[Terms of Service](https://docs.switchagents.ai/legal/terms),
[Data Handling](https://docs.switchagents.ai/legal/data-handling),
[Data Protection Addendum](https://docs.switchagents.ai/legal/dpa).

## Observability / debugging

The plugin keeps all state and a log under Claude Code's own per-plugin data
directory, `${CLAUDE_PLUGIN_DATA}` (e.g. `~/.claude/plugins/data/<plugin-id>/`
— set for every hook invocation, survives plugin updates, cleaned up on
uninstall). Outside a hook invocation it falls back to
`~/.switch-trust/roi_cc_plugin/`:

```
<state dir>/
├── ccusage.log            # what ran, tokens reported, HTTP result, errors
├── <session_id>.cursor    # last processed transcript message per session
├── <session_id>.opened    # SessionOpen-sent marker
├── <session_id>.last_emit # throttle timestamp
├── <session_id>.seq       # next sequence_number (report modes text/full only)
└── user_email             # cached identity
```

Quick checks:

- **Status**: run `/switch-trust-status` in Claude Code — shows where state lives,
  whether config is set, active sessions, and the tail of the log.
- **Check the files manually**: inspect `<state dir>/ccusage.log` and the
  other files listed above directly.

If the Switch Trust API Key setting isn't set, the log will say `no
switch_trust_api_key configured; skipping` — that's the first thing to check.

## License

Source available, not open source: Apache 2.0 as limited by the Commons
Clause license condition, which excludes selling the software or a
derivative of it. See [LICENSE](LICENSE) for the full terms.
