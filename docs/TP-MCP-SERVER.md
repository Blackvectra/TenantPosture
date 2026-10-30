# TenantPosture MCP server (read-only)

`Start-TPMcpServer.ps1` is a local [Model Context Protocol](https://modelcontextprotocol.io)
server over the assessment results this tool has already saved. Registered with an AI
client (Claude Code, Claude Desktop), it lets the assistant answer questions such as
"what changed for contoso since last week?", "which High gaps are open?" or "why was
EXO-1.1 not assessed?" from the results files on this computer.

It is **off by default**. Nothing starts it unless the operator registers it with an AI
client; the client then starts it as a child process when it needs it.

## What it never does

- **It never touches a tenant.** No sign-in, no Microsoft Graph, no Exchange Online, no
  Teams, no Power Platform, no DNS lookup, no network of any kind. It reads files.
- **It never writes.** No file, no folder, no report, no exception record. The results
  files are opened read-only.
- **It never takes a path.** A run is addressed by `(folder, id)` exactly as the web GUI
  addresses it: `tenantposture_list_runs` returns both, and `Lib/Resolve-TPWebRunPath.ps1` (the same
  guard the GUI uses, `-Kind Results`) is the only place an argument becomes a path.
  Segments are an ASCII whitelist; `..`, separators, absolute paths and a real folder
  named `_flat` are refused.
- **It never serves incident-response output.** Email-IR mailbox runs
  (`output\<user>\*-email-results.json`), sign-in triage (`IR-Triage`) and any results
  file carrying `DeepDives` or `EMAIL-*` / `SIGNIN-*` findings are neither listed nor
  returned: they hold sign-in addresses, geolocation and message metadata.
- **It never returns** the raw inventory (`RawData`), the `Exceptions` array, the tenant
  ID, the operator's account, the connection record, the baseline exceptions path or any
  file path. Those parts of a results file are not even materialized: the reader keeps
  only `Metadata`, `Findings`, `Coverage`, `BaselineCompliance`, `ChangeImpact`, each collector's
  `Success` flag and the subscribed SKUs.

`Testing/TP.McpServer.Tests.ps1` runs the real server in a child process and pins each of
these, and statically fails the build if `Start-TPMcpServer.ps1` or a file in `Mcp/`
calls a network, sign-in, tenant, write or process command. The module loader does not
load `Mcp/`, so the module's export list is unchanged.

## Privacy: identities are pseudonymized by default

Everything the server returns is sent to the AI provider behind the client. By default
it replaces people with stable pseudonyms (`user-1`, `user-2`, ...) for the life of the
server process:

1. Every email-shaped string (UPNs, mailbox and SMTP addresses, including Exchange's
   `"x@y" [SMTP:x@y]` form) becomes `user-<n>`.
2. Every value held under an identity key in a finding's `AffectedObjects`
   (`DisplayName`, `UserDisplayName`, `UserPrincipalName`, `Upn`, `Mail`, `Address`,
   `Mailbox`, `User`, `Owner`, `Member`, `Recipient`, `Sender`, and their plurals) is
   learned as an identity when the run is first read, and every later occurrence of it in
   any returned string (`Detail`, `CurrentValue`, a baseline or scope reason) becomes the
   same `user-<n>`.

The map lives in memory only, is never written, and starts empty each time the client
starts the server. Invisible format characters (bidirectional overrides, zero-width
characters, tag characters) are stripped from every returned string.

**What it will miss.** The rule is deliberately simple, so know its limits:

- A person named only in prose (a `Detail` that names someone who is not in any
  finding's `AffectedObjects`) is not recognized unless the name is email-shaped.
- Values under keys outside the list above (a policy `Name` that contains a person's
  name, for example) are not learned.
- Names shorter than three characters, numeric values and GUID-shaped values are not
  learned, so an object ID (`user:<guid>`) is returned as recorded; it identifies an
  account inside the tenant but is not a name.
- It over-redacts too: an application's `DisplayName` in `AffectedObjects` and a shared
  monitoring address (for example a DMARC reporting mailbox) are pseudonymized like a
  person.
- Tenant domains are returned (they label the runs).

`-IncludeIdentities` turns pseudonymization off and returns identities as recorded. Use
it only when the operator accepts sending them to the AI provider; the tenant ID, raw
data, exceptions and paths are still never returned.

## Tenant text is data, not instructions

Policy names, rule names, group names, display names and finding detail come from the
tenant, and anyone who can name a Conditional Access policy or a transport rule chooses
that text. The server returns such strings only as values of JSON fields (never as
instructions or prose of its own), and its `initialize` instructions tell the client the
same. An assistant should treat any instruction-like text inside a field as a property
of the tenant, not as a request.

## Honesty

The tools keep the tool's distinctions:

- Only `Satisfied` is a pass. `NotApplicable`, `Error` and a control with no finding mean
  no verdict was reached, and every answer that lists findings says so.
- A value the results file does not record is reported as not recorded (an older run has
  no maturity label, no baseline view, no coverage), never recomputed or guessed. The one
  exception is stated in its answer: `tenantposture_get_scope` computes the scope section from the
  results file the way a `-FromResults` republish does, because results files do not
  store it, and names what it used and which control catalog.
- `tenantposture_compare_runs` never calls a gap that became `NotApplicable` or `Error` resolved; it is
  `VerdictChanged`.
- `tenantposture_get_change_impact` returns the accounts a risky change would affect only as far as the
  run read them: a block that is `NotRead`, `NotEstablished` or not `Complete` is not a
  list of everyone affected, and `NoneFound` never means nothing can break.
- Coverage lines are labeled as not scores, and no text the server writes says
  "compliant".

## Register it

PowerShell 7 must be on the PATH as `pwsh`. Use the full path to the script.

Claude Code:

```bash
claude mcp add tenantposture -- pwsh -NoProfile -NonInteractive -File /path/to/TenantPosture/Start-TPMcpServer.ps1
```

On Windows, for example:

```powershell
claude mcp add tenantposture -- pwsh -NoProfile -NonInteractive -File C:\Tools\TenantPosture\Start-TPMcpServer.ps1
```

Claude Desktop (`claude_desktop_config.json`, Settings > Developer > Edit Config):

```json
{
  "mcpServers": {
    "tenantposture": {
      "command": "pwsh",
      "args": [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        "C:\\Tools\\TenantPosture\\Start-TPMcpServer.ps1"
      ]
    }
  }
}
```

Parameters:

| Parameter | Meaning |
|---|---|
| `-OutputRoot <folder>` | The output folder to serve. Default `<script folder>\output`, where the assessment, the batch runner and the web GUI write. |
| `-IncludeIdentities` | Return UPNs, addresses and display names as recorded instead of pseudonyms. |

Add either after the script path in the registration (for example
`... -File C:\Tools\TenantPosture\Start-TPMcpServer.ps1 -OutputRoot D:\reports`). Run labels
come from `Config/clients.json` the way the web GUI names a command-line run.

## Protocol

JSON-RPC 2.0 over standard input and output, one message per line; standard output
carries protocol messages only and diagnostics go to standard error. Implemented:
`initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`. Unknown
methods return `-32601`, malformed JSON `-32700`, an invalid request `-32600`, bad
parameters or an unknown tool `-32602`. A tool failure (unknown run, invalid argument) is
an `isError` result with a fixed sentence, never a protocol error, and never echoes the
argument or a path.

Protocol revisions: the initialize-handshake revisions `2025-11-25` (latest),
`2025-06-18`, `2025-03-26` and `2024-11-05`. A supported version asked for in `initialize`
is echoed; any other gets `2025-11-25`. From `2025-06-18` on, every tool declares an
`outputSchema` and returns `structuredContent` beside the text; for older revisions only
the text (the same JSON) is sent. The handshake-free `2026-07-28` revision is not
implemented: a client that probes with `server/discover` receives `-32601` and, as that
revision specifies for dual-era clients, falls back to `initialize`.

Bounds: a results file larger than 256 MB is not read; long strings are cut with a
`[truncated: N more characters]` marker; lists are capped with a
`[truncated: N more items not shown]` entry; an answer over about one million characters
is replaced with an error that says how to narrow the query.

## Tool design

The server follows the MCP builder best practices:

- **Names.** Every tool is `tenantposture_<verb>_<noun>`, so it cannot collide with
  another server's `list_runs`. The names from before the prefix (`list_runs`,
  `get_finding`, ...) are still accepted by `tools/call`, so an existing client
  configuration or saved prompt keeps working, but `tools/list` announces only the
  prefixed names.
- **Annotations.** Every tool declares `readOnlyHint: true`, `destructiveHint: false`,
  `idempotentHint: true` and `openWorldHint: false`. They are hints to the client, not
  the guarantee: the guarantee is the static test that forbids every network, sign-in,
  tenant, write and process command in the server's files.
- **Paging.** `tenantposture_list_runs`, `tenantposture_list_findings` and
  `tenantposture_get_baseline` take `limit` and `offset` and return `total`,
  `returned`, `offset`, `hasMore` and `nextOffset` (`null` on the last page);
  `truncated` is kept and equals `hasMore`. Follow `nextOffset` while `hasMore` is true.
- **Response format.** Every tool takes `response_format`: `json` (the default; the text
  is the JSON answer, as before) or `markdown` (the same answer laid out as headings,
  lists and tables for reading, `Mcp/Format-TPMcpMarkdown.ps1`). The Markdown is built
  from the answer after pseudonymization and capping, and every key and value goes
  through `ConvertTo-TPMarkdownSafe`, so tenant text can form no link, image, code span,
  heading or HTML element. `structuredContent` is JSON either way.
- **Schemas.** Inputs are validated against the declared schema (unknown arguments,
  types, enums, bounds, required); list outputs declare their row shape.
- **Errors.** A tool failure says what to do next (call `tenantposture_list_runs` and
  copy the folder and id; the shape a control ID takes; which filter or offset narrows
  an answer that is too large) and never echoes the argument or a path.

## Evaluation

First model run (2026-10-30, Sonnet through the Claude Code CLI with the builder's
evaluation prompt, one fresh session per question, only this server's tools): 9 of 10.
The miss followed the scope bucket name instead of the baseline reason code, so
`tenantposture_get_finding` now carries the control's baseline row and
`tenantposture_get_scope` takes `controlId` and `bucket` filters; the model's other notes
added `latestForTenant`, named the earlier and later run in `tenantposture_compare_runs`,
pointed `tenantposture_get_control` at the effort class, and say in `response_format`
that a client which displays `structuredContent` shows JSON.
Rerun the same day after those changes: 10 of 10, four to six tool calls per question.
The run listing then gained each run's recorded maturity score and label, so a
cross-tenant comparison needs no summary call per run. The other suggestions (a
count-by-workload option, the effort class inside the change-impact view) save a call
each and are not built.

`tools/mcp-eval/tenantposture-eval.xml` holds ten questions in the MCP builder's
evaluation format, each needing several tool calls (the earliest and latest runs of one
tenant, follow-up calls from one answer to the catalog, paging through 70 findings).
They are asked against the fixed output folder `tools/mcp-eval/New-TPMcpEvalFixture.ps1`
builds (three made-up tenants, five runs), so the answers never change.
`TP.McpServer.Tests.ps1` builds that folder, walks each question's path through the real
server and fails if an answer stops being true. To run the questions against a model,
build the fixture and register the server with `-OutputRoot` pointing at it:

```powershell
$out = ./tools/mcp-eval/New-TPMcpEvalFixture.ps1 -Path ./mcp-eval-work
claude mcp add tenantposture-eval -- pwsh -NoProfile -NonInteractive -File ./Start-TPMcpServer.ps1 -OutputRoot $out
```

## Tools

All tools are read-only (`readOnlyHint: true`, `openWorldHint: false`). Every tool also
takes `response_format?` (`json` or `markdown`), and the three list tools take
`offset?` and return the paging fields above.

| Tool | Input | Returns |
|---|---|---|
| `tenantposture_list_runs` | `tenant?` (label contains, case-insensitive), `limit?` (default 50, max 200) | `runs[]`: `tenant`, `folder`, `id`, `date` (and `dateSource`), `toolVersion`, `controlCount`, `findingCount`, `baselineRecorded`; `total`, `returned`, `truncated`; `latestForTenant` marks each tenant label's newest run (by recorded assessment time; by file date only when no run of that tenant records one); `maturityScore` and `maturityLabel` as the run recorded them (`null` and empty when it recorded none; never recomputed) |
| `tenantposture_get_run_summary` | `folder`, `id` | `run` (domain, dates, tool version, quick scan, declared EDR or awareness product, baseline version and tier), `maturity` (as recorded, or `recorded: false`), `findingInstances` (by state, by severity), `controls` (worst state per control, open by severity), `baseline` (counts, `evidenceCoverage`, `effectivenessCoverage`), `license` (tier label and flags from the run's SKUs, or `read: false`), `notes` |
| `tenantposture_list_findings` | `folder`, `id`, `state?`, `severity?`, `workload?` (ID prefix), `controlId?`, `limit?` (default 50, max 200) | `findings[]`: `controlId`, `title`, `state`, `severity`, `workload`, `instance`, short `detail`; `total`, `returned`, `truncated`, `note` |
| `tenantposture_get_finding` | `folder`, `id`, `controlId` | every instance for the control (state, detail, current and required value, remediation, framework citations, affected objects capped at 50, coverage), `worstState`, `note`; no finding is stated as not a pass; `baseline`: the control's NRG Security Baseline row as the run recorded it (tier, observed state, status, `reasonCode`, `reason`), or `recorded: false` / `inBaseline: false` |
| `tenantposture_get_control` | `controlId` | `control` (from `Config/controls.json`), `benchmarks` (`Get-TPBenchmarkMapping`: items, or the reason it is unmapped), `operationalImpact` (`Config/operational-impact.json`, or "Operational impact not documented", never "no impact"), `baseline` (its NRG Security Baseline row, or assessment-only) |
| `tenantposture_compare_runs` | `folderA`, `idA` (the earlier run), `folderB`, `idB` (the later run) | `runA`, `runB`, `changed[]` (before, after, `Improved` / `Regressed` / `VerdictChanged`), `newGaps[]`, `resolvedGaps[]`, `onlyInA[]`, `onlyInB[]`, `unchangedCount`, `notes`. Refused unless both runs carry the same tenant ID (the guard `Publish-TPDeltaReport` applies); two different tenants are compared with `Compare-TPTenantBaseline.ps1`, offline |
| `tenantposture_get_baseline` | `folder`, `id`, `status?` (`Satisfied`, `Failed`, `NotVerified`, `NotApplicable`, `LicenseBlocked`, `ApprovedException`), `limit?` (default 100, max 200) | the recorded `BaselineCompliance`: version, tier, summary, both coverage lines, `rows[]` (`controlId`, `title`, `tier`, `observedState`, `baselineStatus`, `constraint`, `disposition`, `effectivenessState`, `reasonCode`, `reason`), or `recorded: false` |
| `tenantposture_get_scope` | `folder`, `id`, `bucket?` (one bucket's controls), `controlId?` (why this one control reached no verdict) | `computed`, `basis`, control counts, `buckets` (`CollectionIncomplete`, `NoResult`, `Errors`, `StandardNotApproved`, `SkippedByOperator`, `NotEvaluatedThisMode`, `LicenseBlocked`, `ThirdPartyAttested`, `NoProgrammaticCheck`, `NotApplicableToTenant`, each with its controls and reasons), `coverageIssues`, `limitations`; every bucket keeps its `count` under a filter, and `filter` says what was narrowed |
| `tenantposture_get_change_impact` | `folder`, `id`, `list?` (`implementNow`, `needsPlanning`, `couldBreakAccounts`, `licenseDecision`), `controlId?` | the change-impact view the run recorded: `summary`, the four lists (each risky change with `Why`, its `Evidence` blocks naming accounts, each block's `Status` `Named` / `NoneFound` / `NotEstablished` / `NotRead` and `Complete`, `Unseen`, and its `EmergencyAccess` reminder), `emergencyAccess`, `scopeNotice`, `note`; `recorded: false` for a run made before the view existed (not recomputed; republish with `-FromResults`). Account names are pseudonymized like every other identity |

## Files

| File | Role |
|---|---|
| `Start-TPMcpServer.ps1` | Entry point: imports the psm1 (not the manifest, so no Graph module is needed), loads the run index and the path guard, serves until standard input closes. |
| `Mcp/Invoke-TPMcpProtocol.ps1` | JSON-RPC framing, version negotiation, method dispatch. |
| `Mcp/Invoke-TPMcpTool.ps1` | Tool definitions (input and output schemas), argument validation, the nine tools. |
| `Mcp/Read-TPMcpRun.ps1` | Bounded results-file reader (`JsonDocument`; only the parts listed above are materialized). |
| `Mcp/Protect-TPMcpOutput.ps1` | Pseudonymization, format-character stripping, truncation. |
| `Mcp/Format-TPMcpMarkdown.ps1` | The Markdown layout for `response_format: markdown`. |
| `tools/mcp-eval/` | The evaluation questions and the fixture they are asked against. |
| `Lib/Resolve-TPWebRunPath.ps1` | The path guard, shared with the web GUI (`-Kind Results`). |
| `Lib/Get-TPWebRunIndex.ps1` | The run listing, shared with the web GUI. |
