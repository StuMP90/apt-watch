# aptwatch — Specification & Plan

Status: **Draft v0.6** (2026-10-22): decisions from review recorded in [§12](#12-decisions-and-open-questions); v0.6 adds `aptwatch cve` (§3.1) and first-seen dates for Debian CVEs (§6.2).

---

## 1. Purpose

A single static Go binary, run daily as root (cron or systemd timer) on Debian and Ubuntu servers, that:

1. Inventories installed packages and the system state that affects patching (kernel, reboot, services that need restarting, OS end-of-life).
2. Works out which updates are available, and which of those are **security** updates.
3. Matches installed packages against known CVEs, enriched with "known exploited" (CISA KEV) and exploit-probability (EPSS) data.
4. Scores everything into **findings** with a severity, compares them with the previous run, and produces a report.
5. Writes the report to standard output as text (default), self-contained HTML or JSON. It sends nothing itself: cron mails the output, or it is redirected to a file or piped to a separate handler.

### Non-goals (v1)

- Installing updates. `unattended-upgrades` already does that; this tool **reports**.
- Delivering the report (email, chat, pop-ups, …). That is left to cron, a redirect or a pipe (§11.2).
- RPM-based distros, containers/images, language package managers (pip, npm, …).

### Supported platforms

| Distro | Releases | Arch |
|---|---|---|
| Debian | 12 (bookworm), 13 (trixie) | amd64, arm64 |
| Ubuntu | 22.04, 24.04, 26.04 LTS (non-LTS best-effort), with or without Ubuntu Pro | amd64, arm64 |

All hosts are assumed to have direct internet access (no mirror or proxy needed in v1).

---

## 2. Key design decisions

| Decision | Choice | Reason |
|---|---|---|
| Language | Go (current stable), `CGO_ENABLED=0` | One static binary, no runtime deps, easy to copy to any host. |
| Privilege | Runs as root | Can run `apt-get update`, read every package changelog, and see every process for restart checks. |
| Package data | Parse `/var/lib/dpkg/status` directly; use `apt-get -s dist-upgrade` for candidates | No libapt bindings in Go. Both formats are stable and machine-oriented. apt resolves pinning and phasing for us. |
| Version comparison | Own `debver` package (Debian policy §5.6.12 algorithm) | Small, well specified, heavily tested; avoids a dependency. |
| CVE data | Debian: Security Tracker JSON. Ubuntu: OSV bulk export (Canonical-published). KEV and EPSS from CISA/FIRST. | Authoritative per-distro data, with fixed versions per release. Sources sit behind an interface so they can be swapped. |
| Output | The report goes to stdout as `text`, `html` or `json`; no built-in delivery | Unix-style: cron's `MAILTO`, `> file` and `| handler` cover email, web pages and anything else, with no SMTP code, credentials or delivery state in a root tool. |
| Config | YAML, `/etc/aptwatch/config.yaml` | Readable, supports comments, `gopkg.in/yaml.v3`. |
| Dependencies | Minimal: `yaml.v3`, `spf13/cobra` (CLI). Everything else stdlib. | Smaller supply-chain surface for something that runs as root. |

---

## 3. Command-line interface

```
aptwatch run            Full pipeline: refresh → collect → match → evaluate → diff → report (stdout)
    --no-refresh           Skip apt-get update and vuln DB refresh (use cached data)
    --dry-run              Don't refresh and don't update the state file
    --format text|html|json   Report format (default: report.format in the config, else text)
    --nagios               Print one Nagios status line instead of the report (§3)

aptwatch scan           Collect and match only; print the report (no state)
    --format text|html|json
    --nagios
aptwatch cve CVE-ID...  Report whether the host is affected by the given CVEs and what fixes them (§3.1)
    --format text|html|json
    --no-refresh           Use only cached vulnerability data
aptwatch db update      Refresh vulnerability data caches only
    --force                Check every feed, however recently it was checked
aptwatch db status      Show each data source, age, size, last error
    --json
aptwatch config check   Validate config and file permissions; exit non-zero on error
aptwatch state show     Show stored findings with first-seen dates
aptwatch state reset    Forget history (next run treats everything as new)
aptwatch version
```

Global flags: `--config PATH` (default `/etc/aptwatch/config.yaml`), `--log-level`, `--quiet`.

`run --no-notify` (from earlier versions) is still accepted and does nothing.

### Exit codes (so it also works as a monitoring check)

| Code | Meaning |
|---|---|
| 0 | No findings at or above `policy.exit_threshold` |
| 1 | Findings at or above the threshold |
| 2 | Run completed with warnings (stale data, a source failed) |
| 3 | Fatal error (bad config, couldn't collect package data) |

If there are both risks and warnings, the code is **1**. Suppressed findings (§7.3) don't count.

`run --nagios` and `scan --nagios` print one line instead of the report, `STATUS - <summary>[ — N warnings: <first>]`, and exit with the Nagios code:

| Code | Status | When |
|---|---|---|
| 0 | OK | No active findings at or above Low, and no warnings |
| 1 | WARNING | Active findings below `policy.exit_threshold` (but at least Low), or warnings |
| 2 | CRITICAL | Active findings at or above `policy.exit_threshold` |
| 3 | UNKNOWN | Fatal error, printed to stdout as `UNKNOWN - aptwatch: <error>` |

`db update` exits 2 if a feed failed but a cached copy is in use, 3 if no advisory data could be loaded. `db status` reads the cache alone (it downloads nothing) and exits 2 if a feed has never been downloaded, its last refresh failed, or it is older than `vulndb.stale_after`. `config check` exits 3 if the config is invalid or its permissions are wrong (§10.1), 2 if it loaded with warnings or has expired ignore rules, else 0.

For `aptwatch cve`, the code is **1** if any CVE needs action (status `fix-pending`, `fix-unreachable`, `fix-requires-pro`, `reboot-pending`, `no-fix` or `unconfirmed`), else **2** if any is `unknown` or there were warnings, else **0**. An argument that isn't a CVE ID is fatal (**3**). The exit-code thresholds and ignore rules don't apply: the caller asked about these CVEs.

### 3.1 Checking specific CVEs: `aptwatch cve`

`aptwatch cve CVE-2026-109618 CVE-2026-109619` answers "is this host affected, and is it fixed?" for each CVE (case-insensitive, duplicates dropped). It collects the inventory and opens the vulnerability data as `scan` does (no state, no lock, refreshing out-of-date data unless `--no-refresh`), then works out a status for every installed source package that the CVE affects:

| Status | Meaning |
|---|---|
| `fix-unreachable` | Fixed in a version apt can't install from the configured sources (pins, holds, missing pocket) |
| `fix-requires-pro` | Fixed only in Ubuntu Pro (ESM), which isn't enabled |
| `fix-pending` | A pending update fixes it; the report gives the `apt-get install --only-upgrade` command |
| `reboot-pending` | The fix is installed but not running: in a newer kernel than the running one, or in a package that `/run/reboot-required.pkgs` names |
| `no-fix` | The distribution hasn't published a fix yet |
| `unconfirmed` | Third-party package: the distribution fixed the CVE in its own build, but the third-party changelog doesn't name it |
| `unknown` | Can't tell, e.g. a third-party package whose changelog wasn't read |
| `fixed` | The installed version contains the fix (by version for distribution packages, by the installed changelog for third-party ones) |
| `not-affected` | Overall only: the data knows the CVE, but no affected package is installed |

Distribution packages are judged by their advisory as in §6.4; third-party ones by their changelogs as in §6.4's changelog rules. Old kernels are skipped and the newest one's status counts. The CVE's overall status is the package status highest in the table. A CVE that is neither in the data for this release nor in any changelog read is `unknown`, with a note that it may be too new, rejected, mistyped or not apply to this distribution.

The report gives, per CVE: priority, publish date, KEV (with the date added) and EPSS; the description and tracker link; a table of the affected installed packages (installed → candidate version, fixed-in version, status, repository) with notes and commands; and the affected packages that aren't installed. Formats are as in §9.2, and the HTML page uses the same style sheet.

---

## 4. Pipeline

```
 ┌─────────┐  ┌──────────┐  ┌────────┐  ┌──────────┐  ┌──────┐  ┌────────┐
 │ refresh │→ │ collect  │→ │ match  │→ │ evaluate │→ │ diff │→ │ report │→ stdout
 └─────────┘  └──────────┘  └────────┘  └──────────┘  └──────┘  └────────┘
  apt lists    dpkg, apt     CVE DBs     policy →      state     text, html
  vuln DBs     system info   + KEV/EPSS  Findings      file      or json
```

The run takes an exclusive `flock` on `/run/aptwatch.lock`. A second run exits immediately with code 3 and a clear message.

Each stage records **warnings** (non-fatal problems such as a failed download) that go into the report. Only a failure to read the dpkg database is fatal.

---

## 5. Collection

### 5.1 Refreshing apt lists

- If `apt.refresh_lists: true` and the newest file in `/var/lib/apt/lists` is older than `apt.refresh_if_older_than` (default `6h`), run
  `apt-get update -qq -o DPkg::Lock::Timeout=<apt.lock_timeout>` with `LC_ALL=C`.
  The lock timeout (default `10m`) avoids failing while `apt-daily` or `unattended-upgrades` holds the lock.
- If the lists are still older than `apt.stale_after` (default `48h`), raise a `stale-apt-lists` finding.
- `refresh_lists: false` relies on the system's `apt-daily.timer` instead.

### 5.2 Installed packages: `/var/lib/dpkg/status`

Parse the RFC 822-style stanzas. For each package whose `Status` is `install ok installed` (also record `hold`), keep:

| Field | Use |
|---|---|
| `Package`, `Architecture`, `Version` | Identity and installed version |
| `Source` | Source package name and version. Format is `name` or `name (version)`; if absent, use `Package`/`Version`. **CVE data is keyed by source package.** |
| `Status` first word `hold` | Held package |

Also read held packages from `apt-mark showhold` to be safe.

### 5.3 Available updates: `apt-get -s dist-upgrade`

Run `LC_ALL=C apt-get -s -o Debug::NoLocking=true dist-upgrade` and parse its lines:

```
Inst libssl3 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst linux-image-6.8.0-90-generic (6.8.0-90.91 Ubuntu:24.04/noble-updates [amd64])      ← new install, no [old]
Remv foo [1.2-3]
```

For each `Inst`, record: package, old version (if present), candidate version, and the list of `origin/suite` labels.

- **Security update**: any suite matching `*-security` (Ubuntu, Debian 12/13 `bookworm-security`, `trixie-security`), or the origin `Debian-Security`.
- **ESM**: origin `UbuntuESM` / `UbuntuESMApps`. Mark these "requires Ubuntu Pro".
- **Kept back / phased**: also run `apt-get -s upgrade` and compare. Packages in `dist-upgrade` but not in `upgrade` are "needs new dependencies". apt's phasing output on Ubuntu (`deferred due to phasing`) is recorded so phased updates aren't reported as overdue.
- **Held** packages that have a candidate are reported, at higher severity if the candidate is a security update.

`apt-cache policy <pkg>` is only used as a fallback for unclear cases (e.g. to get the origin for a package that the simulation doesn't show).

### 5.3a Package repositories: `/var/lib/apt/lists`

Each installed package is tied to the repository it came from, so that third-party builds (PPAs, `packages.sury.org`, `apt.postgresql.org`, NodeSource, vendor repos) aren't judged against the distribution's CVE data.

- Each `*InRelease` / `*Release` file gives a repository and its `Origin`. `Ubuntu`, `UbuntuESM`, `UbuntuESMApps`, `Debian` and `Debian Backports` are **official**; everything else is third-party. The repository's display name comes from the file name prefix (`packages.sury.org_php_dists_noble_` → `packages.sury.org/php`).
- Each `*_Packages` / `*_Packages.gz` file belongs to the repository with the longest matching prefix. Only the `Package` and `Version` lines of installed package names are kept (about 1 s for 200 MB of lists).
- For each installed package:
  - If a repository offers the installed version, the package comes from it. An official repository wins if several offer it.
  - If none does (the version has been superseded), the package counts as **third-party** if a third-party repository offers the name and the installed version is above every version the distribution offers. Otherwise it counts as official.
  - If no repository offers the name at all, the package is **local** (`dpkg -i`, or a removed repo).
- `InDistro` records that the distribution also ships a package of that name, i.e. the third-party build replaces the distribution's.
- If the lists can't be read, nothing is classified, and a warning is shown. An index that can't be read stops packages being marked local.

### 5.3b Third-party changelogs (`vulndb.changelogs`, default on)

The distribution's CVE data doesn't cover third-party builds (§6.4), but their Debian changelogs often name the CVEs each version fixes (Sury PHP, PGDG). For each third-party source package (§5.3a):

- **Installed**: `/usr/share/doc/<binary>/changelog.Debian.gz` (or `changelog.gz` for native packages). Binaries with their own doc directory are tried first, since the rest are often symlinks to another package's.
- **Pending update**: the candidate's changelog, which also covers the installed version. Third-party repositories rarely support `apt-get changelog`, so the `.deb` is fetched with `apt-get download` (into a temp directory under the cache, writable by `_apt`), and `dpkg-deb --fsys-tarfile` is streamed until the changelog is found. At most three binaries are tried per source.
- If there's no `/usr/share/doc` (a minimized image), the installed version is downloaded the same way, if the repository still has it.
- Entries are parsed as `source (version) dist; urgency=…` headers; every `CVE-YYYY-NNNN+` in an entry belongs to that version. A file without such headers (an upstream changelog) is rejected.
- CVEs in entries ≤ the installed version are **fixed**. Those in entries above it and ≤ the candidate are **pending**. Snapshot builds (`+0~20261021.121+ubuntu24.04~1.gbp…`) sort below the release they snapshot, so their entries still count.
- Results for downloaded `.deb`s are cached in `<cache_dir>/changelogs/<name>=<version>.json`, including "no changelog in the package" (so a large vendor `.deb` is fetched once per version). Entries for versions no longer installed or pending are removed.
- A package that ships no changelog isn't a warning: its repository's `third-party-packages` finding already says it can't be checked. Other failures (download, parse) are warnings.

### 5.4 System state

| Item | Source | Finding |
|---|---|---|
| OS ID, version, codename | `/etc/os-release` | Used to select CVE data |
| OS end-of-life date | `/usr/share/distro-info/{debian,ubuntu}.csv` (package `distro-info-data`, present by default). Fall back to a table built into the binary. | `os-eol` (approaching / passed). For Ubuntu, also note the ESM date. |
| Reboot required | `/run/reboot-required` (+ `.pkgs`); file mtime gives age | `reboot-required` |
| Running vs newest installed kernel | `uname -r` vs installed `linux-image-*` packages | `kernel-not-running` |
| Services using outdated libraries | `needrestart -b -r l` if installed (parse `NEEDRESTART-SVC:` / `NEEDRESTART-KSTA:`). Otherwise scan `/proc/*/maps` for mapped files marked `(deleted)` under `/usr/lib` or `/lib` and map PID → systemd unit using `/proc/PID/cgroup`. | `service-restart-needed` |
| Livepatch (Ubuntu, optional) | `canonical-livepatch status --format json` if present | Lowers the severity of `kernel-not-running` when the patch is applied |
| Ubuntu Pro status | `pro status --format json` if present | Decides whether ESM fixes count as "fix available" or "fix requires Pro" |

All external commands run with an explicit argv (never through a shell), `LC_ALL=C`, a timeout, and a minimal environment.

---

## 6. Vulnerability data

### 6.1 Source interface

```go
type VulnSource interface {
    Name() string
    Supports(os OSInfo) bool
    Refresh(ctx context.Context, cache *Cache) error  // conditional download (ETag / If-Modified-Since)
    Lookup(srcPkg string, os OSInfo) []Advisory       // all advisories for this source package and release
}

type Advisory struct {
    CVE          string    // CVE-YYYY-NNNN (or USN/DSA ID if no CVE)
    Aliases      []string
    SourcePkg    string
    FixedVersion string    // "" = no fix in this release
    Status       string    // fixed | open | not-affected | ignored | postponed | end-of-life
    Priority     string    // normalised: negligible | low | medium | high | critical | unknown
    Description  string
    URL          string
}
```

### 6.2 Sources

| Source | Distro | URL (confirmed in M2) | Notes |
|---|---|---|---|
| Debian Security Tracker | Debian | `https://security-tracker.debian.org/tracker/data/json` | One JSON file: source package → CVE → release → `{status, fixed_version, urgency}`. Same data `debsecan` uses. |
| OSV bulk export | Ubuntu | `https://security-metadata.canonical.com/osv/osv-all.tar.xz` | Canonical's own export (about 50 MB compressed). Uses the `osv/cve/` records; filter on `affected[].package.ecosystem` such as `Ubuntu:24.04:LTS` and `Ubuntu:Pro:…`. A range with no `fixed` event is unfixed. Priority comes from `severity` / `ecosystem_specific`. Fixes released in the last day or two may not be in it yet: those updates still show as plain security updates. |
| CISA KEV | All | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Set of CVE IDs known to be exploited, with date added. |
| FIRST EPSS | All (optional) | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | Probability of exploitation in the next 30 days, per CVE. |

**Publish dates for Debian.** The Debian tracker gives no publish dates, so aptwatch records the day it first sees each CVE in the tracker data for the release, in `<cache_dir>/debian-<release>-seen.json`, and uses that as the date. CVEs already there on the first run are recorded without a date: they were published at some unknown time before, so none counts as recent (`policy.recent_cves`). Entries are kept when a CVE leaves the data, so one that comes back isn't dated again; a corrupt file, or one for another release, starts afresh. A CVE still without a date takes the date CISA added it to KEV, if it is there, since it was public by then at the latest. Ubuntu's OSV data has real publish dates and doesn't need this.

Other sources (Ubuntu OVAL, OSV `querybatch` API) can be added through the same interface later. NVD CVSS scores are not used: NVD rate-limits its API, and the distro's own priority is more relevant to the packaged version than NVD's generic score.

### 6.3 Caching and failure handling

- Cache directory `/var/cache/aptwatch/` (mode 0700). One file per source plus a `meta.json` holding ETag, Last-Modified, fetch time and SHA-256.
- Refresh when older than `vulndb.max_age` (default `20h`), using conditional GET.
- Downloads go to a temp file, are checked (size limit, valid JSON/zip), then renamed into place. A bad download never replaces good cached data.
- HTTPS only, with timeouts and a maximum size (default 1 GiB per source, configurable).
- If a refresh fails and cached data exists, use it and add a `stale-vuln-data` warning once it's older than `vulndb.stale_after` (default `72h`). If there's no cache at all, CVE matching is skipped with a warning; update reporting still works.
- Each source is parsed into a compact index, stored as gob in the cache directory, so later runs don't re-parse hundreds of MB.

### 6.4 Matching

For each installed **source** package (from §5.2) and each advisory for it in the host's release:

| Condition | Result |
|---|---|
| `Status` is `not-affected`, or installed version ≥ `FixedVersion` | Not vulnerable; ignore |
| `FixedVersion` set, installed < fixed, and **candidate** ≥ fixed | **Vulnerable, fix available** (`cve-fix-available`) |
| `FixedVersion` set, installed < fixed, but candidate < fixed or no candidate | **Fix exists but can't be installed** (`cve-fix-unreachable`): usually a held package, a missing `-security` repo, or ESM without Pro |
| No `FixedVersion` (open / postponed / ignored) | **Vulnerable, no fix** (`cve-unfixed`) |

All comparisons use `debver.Compare`. A CVE that affects several binary packages from the same source becomes **one** finding listing the binary packages.

**Third-party packages.** A source package whose installed binaries all come from third-party repositories (§5.3a) isn't matched: the distribution's advisories describe the distribution's builds. Without this, Sury's `php8.3` 8.3.36-1 would count as fixed for every Ubuntu advisory fixed in 8.3.6-0ubuntu0.24.04.x, just because its version sorts higher. A source with any official binary is still matched. These packages are reported by `third-party-packages` instead, and judged by their changelogs (§5.3b):

| Condition | Result |
|---|---|
| CVE named in the pending update's changelog but not the installed one | `cve-fix-available`, as for distribution packages. The fixed version is the candidate. |
| CVE named in the installed changelog and published within `policy.recent_cves` (default 90d) | One `cve-fixed-third-party` finding per source (Info), listing those CVEs with their priorities. This shows that a recent fix has arrived, e.g. `php8.3 8.3.36-1+0~20261021… from packages.sury.org/php fixes 15 recent CVEs: … CVE-2026-109618 (critical), CVE-2026-109619 (critical) …` |
| CVE that the distribution fixed in its own build of a **same-named** source, published within `recent_cves`, but named in neither changelog | `cve-third-party-unconfirmed` (`policy.report_third_party_gaps`, default on). Only checked when the changelog names at least one CVE: a changelog that never names CVEs can't be judged by what it leaves out. |

Changelog CVEs are looked up by ID in all of the host's advisories (whichever source package they were filed under) for priority, publish date and description. A CVE with no advisory still gets a `cve-fix-available` finding (Medium by default), but can't be judged recent.

Limits:
- **The recency features are Ubuntu-only.** Only the OSV export has a publish date. The Debian Security Tracker has none, so on Debian there are no `cve-fixed-third-party` or `cve-third-party-unconfirmed` findings; pending-update CVEs still work.
- Gap matching is by source name only (Sury's `php8.3` ↔ Ubuntu's `php8.3`). A third-party source with another name (e.g. `postgresql-18` when Ubuntu ships `postgresql-16`) is never matched, and a fix may be in the package under another description, so a gap is a prompt to check, not proof.
- A changelog can only show what its maintainer wrote down. The `third-party-packages` note says so.

**Kernels.** Kernel binaries carry their ABI in the name (`linux-modules-6.8.0-91-generic`), so old kernels stay installed at their old versions and never get an upgrade. Like `debsecan` and Ubuntu's OVAL data, only the source that builds the newest installed kernel (the one that runs after a reboot) is matched. Other kernel sources are skipped, and the time until the reboot is covered by `reboot-required` / `kernel-not-running`.

---

## 7. Findings and risk evaluation

### 7.1 Finding model

```go
type Severity int // Info < Low < Medium < High < Critical

type Finding struct {
    Key        string    // stable ID used for diffing, e.g. "cve:CVE-2026-1234:openssl", "reboot-required"
    Kind       string    // see table below
    Severity   Severity
    Title      string
    Packages   []PkgRef  // name, installed, candidate, origin
    CVEs       []CVERef  // id, priority, KEV, EPSS, URL
    FixAvail   bool
    Since      time.Time // when the condition started (e.g. update first published / reboot file mtime), if known
    FirstSeen  time.Time // filled in from state
    Detail     string
    Suppressed *Suppression // set if an ignore rule matched (still shown in full reports)
}
```

### 7.2 Finding kinds and default severities

| Kind | Default severity | Escalation (configurable) |
|---|---|---|
| `cve-fix-available` | From distro priority: critical→Critical, high→High, medium→Medium, low/negligible→Low | **In KEV → Critical.** EPSS ≥ `epss_bump` (default 0.5) → +1 level. Pending longer than `escalate_after` (default 7d) → +1 level. |
| `cve-fix-unreachable` | Same as above, +1 level | Same as above |
| `cve-unfixed` | Info | In KEV → High |
| `security-update-pending` (security update with no matched CVE) | Medium | After `escalate_after` → High |
| `update-pending` (non-security) | Info | — |
| `held-security-update` | High | — |
| `reboot-required` | Medium | After 7d → High |
| `kernel-not-running` | Medium | Livepatch applied → Low |
| `service-restart-needed` | Low | Service uses a library with a KEV/High CVE fix → High |
| `os-eol` | Medium within 90d of EOL; High after EOL | Ubuntu with Pro/ESM active → Medium |
| `stale-apt-lists` | Medium | — |
| `cve-fixed-third-party` (one per third-party source, §6.4) | Info: listed in its own report section, not in Findings | — |
| `cve-third-party-unconfirmed` (§6.4) | The distribution's priority −1 level, at least Low | In KEV → High |
| `third-party-packages` (one per repository, §5.3a) | Low if the repository replaces any distribution package (e.g. Sury PHP, PGDG, NodeSource); Info otherwise | — |
| `stale-vuln-data`, `source-error` | Warning (shown in report, affects exit code 2, not severity) | — |

Severities only ever go up through escalation, capped at Critical.

### 7.3 Ignore rules

Configured suppressions, each with a **reason** and an optional **expiry**. Suppressed findings don't trigger alerts or count toward the exit code, but they're listed in full status reports so nothing is hidden for ever.

```yaml
ignore:
  - cve: CVE-2025-12345
    reason: "Vulnerable feature not compiled in; see ticket OPS-412"
    until: 2026-12-31
  - package: "linux-image-*"       # glob
    kinds: [update-pending]
    reason: "Kernel updates handled in monthly window"
```

Matching:

- A rule needs a `cve` or a `package`, and always a `reason`. Unset fields match anything. CVE IDs are normalised (case-insensitive), and unknown kinds are a config error.
- `package` is a shell glob matched against the finding's source package and each of its binary packages; any match counts.
- `cve` matches a finding that names that CVE. A finding naming several CVEs (e.g. one security update fixing three) is suppressed by CVE rules only when they cover **all** of them, so a new CVE in the same update shows up again. A rule without `cve` suppresses on its own.
- `until` is the last day the rule applies (inclusive, in UTC). After that it is expired: its findings count again.

Suppressed findings stay in the state file (so first-seen dates survive) but are left out of the summary, the exit code, the Nagios status and "changes since last run". Every report lists them under "Suppressed findings" with the rule and reason (JSON: `findings[].suppressed`). Expired rules are listed there too (JSON: `expired_ignores`), and `config check` reports them as warnings.

---

## 8. State and change detection

File: `/var/lib/aptwatch/state.json` (mode 0600), written atomically (temp file + rename).

```json
{
  "version": 1,
  "last_run": "2026-10-22T06:25:00Z",
  "findings": {
    "cve:CVE-2026-1234:openssl": { "first_seen": "...", "last_seen": "...", "severity": "high" }
  }
}
```

Each run compares current findings with stored ones:

- **New**: not previously present.
- **Escalated**: severity has gone up.
- **Resolved**: present last time, gone now.
- **Persisting**: still present. Age = now − `first_seen`.

Resolved entries are removed after `state.keep_resolved` (default 30d).

---

## 9. Reports

### 9.1 Content

1. **Header**: host label, FQDN, OS and version (+ EOL date), running kernel, scan time, apt lists age, vuln data age per source, tool version.
2. **Summary line**: e.g. `web01: 2 CRITICAL, 3 HIGH, 5 MEDIUM — 14 updates pending (9 security) — reboot required (3d)`.
3. **Changes since last report**: new, escalated, resolved.
4. **Findings by severity** (Critical → Low): package, installed → candidate, CVEs with KEV ★ marker, EPSS, age, link.
5. **Recent CVEs fixed in installed third-party packages** (`cve-fixed-third-party`, §6.4).
6. **Pending updates**: security and other updates in separate tables.
7. **System**: reboot, kernel, services to restart, held packages, EOL.
8. **Suppressed findings** (full reports only).
9. **Warnings**: data sources, stale lists, config problems.
10. **Suggested commands**, e.g. `apt-get install --only-upgrade openssl libssl3`, `systemctl restart nginx`.

### 9.2 Formats

Chosen with `--format`, or `report.format` in the config (default `text`). Every format carries the same content.

| Format | Use |
|---|---|
| `text` (default) | Terminal and cron mail. Plain text, no colour codes. |
| `html` | A single self-contained page: inline CSS (light and dark), no scripts, nothing fetched, untrusted text escaped by Go's `html/template`. Save it for a web server, or hand it to a mailer as an HTML body. |
| `json` | Stable, versioned schema (`schema` field); for scripts and handlers. |

The first line of `text` output, and the `<title>`/`<h1>` of `html`, is the summary line, so a handler can use it as a subject.

---

## 10. Configuration

### 10.1 Files and permissions

| Path | Mode | Purpose |
|---|---|---|
| `/etc/aptwatch/config.yaml` | 0600 root | Main config |
| `/var/cache/aptwatch/` | 0700 | Vuln data cache |
| `/var/lib/aptwatch/state.json` | 0600 | State |

`config check` **fails** (exit 3) unless the config is owned by root and not writable by group or others (it's read by a root process), whoever runs it. `run` and `scan` apply the same check when run as root. The config holds no secrets.

### 10.2 Example

A `notify:` section from earlier versions is ignored with a warning.

```yaml
host_label: web01                 # default: short hostname

apt:
  refresh_lists: true
  refresh_if_older_than: 6h
  lock_timeout: 10m
  stale_after: 48h

vulndb:
  sources: [auto]                 # auto = debian-tracker on Debian, osv-ubuntu on Ubuntu
  kev: true
  epss: true
  max_age: 20h
  stale_after: 72h
  cache_dir: /var/cache/aptwatch
  max_size: 1GiB                  # per download
  changelogs: true                # read third-party changelogs for CVEs (§5.3b)

policy:
  exit_threshold: high
  escalate_after: 7d
  epss_bump: 0.5
  reboot_escalate_after: 7d
  eol_warn_before: 90d
  report_unfixed_cves: summary    # none | summary | full
  recent_cves: 90d                # third-party changelog CVEs published this recently are reported; 0 = off
  report_third_party_gaps: true   # recent distro CVEs missing from a same-named third-party changelog

ignore:
  - cve: CVE-2025-12345
    reason: "Feature disabled; OPS-412"
    until: 2026-12-31

report:
  format: text                    # text | html | json; --format overrides
```

---

## 11. Packaging and scheduling

### 11.1 Build and packaging

- `CGO_ENABLED=0`, `-trimpath`, version stamped via `-ldflags`. Builds for `linux/amd64` and `linux/arm64`.
- `.deb` built with **nfpm** (or GoReleaser): binary in `/usr/sbin/aptwatch`, example config, cron file, systemd units, and a man page generated from cobra. `Recommends: needrestart, distro-info-data`.
- Signed checksums for releases. Optionally a small apt repository later.

### 11.2 Scheduling (both shipped; the admin enables one)

- **cron**: `/etc/cron.d/aptwatch` → `25 6 * * * root /usr/sbin/aptwatch run --quiet`. cron mails stdout to `MAILTO` when the host can send mail.
- **systemd**: `aptwatch.timer` (`OnCalendar=daily`, `RandomizedDelaySec=1h`, `Persistent=true`) + `aptwatch.service` (`Type=oneshot`). The service adds hardening that doesn't break the tool: `ProtectHome=read-only`, `PrivateTmp=yes`, `ProtectKernelTunables=yes`, `RestrictSUIDSGID=yes`, and `ReadWritePaths` for the cache, state and apt lists. The report goes to the journal (`journalctl -u aptwatch`); use `StandardOutput=file:` or a wrapper script to send it elsewhere.
- Delivery is by redirect or pipe. The exit code (§3) lets a wrapper act only on risks:

```sh
# cron mails the text report
MAILTO=ops@example.com
25 6 * * * root /usr/sbin/aptwatch run

# an HTML page for a web server (written atomically)
25 6 * * * root /usr/sbin/aptwatch run --format html > /var/www/status/web01.html.tmp; mv /var/www/status/web01.html.tmp /var/www/status/web01.html

# hand the JSON to any handler (mailer, chat bot)
25 6 * * * root /usr/sbin/aptwatch run --format json | /usr/local/bin/report-handler
```

- The run waits a random 0–`jitter` (default 0 for cron, systemd handles it) so many hosts don't hit the data sources at the same moment.

---

## 12. Decisions and open questions

### Decided (2026-10-22)

| Topic | Decision | Effect on the spec |
|---|---|---|
| Name | `aptwatch` | Avoids confusion with Ubuntu's `/usr/lib/update-notifier/apt-check`. |
| Notifications | **Removed (2026-10-22).** aptwatch writes the report to stdout as `text` (default), `html` or `json`; cron mail, redirects or a separate handler deliver it. | §3, §9.2, §11.2. Supersedes the earlier email/desktop/chat targets and the notifier package. |
| Build order | End-to-end slice first, tested on the development machine (Ubuntu 24.04 desktop) | M1 is a working slice that prints the report (§15). |
| Ubuntu Pro | Some Ubuntu hosts are on Pro | ESM handling (§5.3, §5.4, §6.2 `Ubuntu:Pro:*` ecosystems, §6.4 "fix requires Pro") is **in v1**, with test coverage on a Pro host (§14). |
| Releases | Debian 12/13, Ubuntu 22.04/24.04/26.04 | As in §1. |
| Network | All hosts have internet access | No mirror or proxy support in v1. |
| Checking one CVE | `aptwatch cve CVE-ID...` with its own statuses and exit codes | §3, §3.1. |
| Debian publish dates | First-seen dates kept in the cache, falling back to KEV's date added | §6.2. The first run on a Debian host reports no third-party CVEs as recent. |

### Still open

None.

---

## 13. Code layout

```
cmd/aptwatch/           main.go, cobra commands
internal/config/        load, defaults, validation, permission checks
internal/debver/        Debian version parsing and comparison
internal/collect/
    dpkg.go             /var/lib/dpkg/status parser
    apt.go              apt-get update, -s dist-upgrade/upgrade parsing, holds
    repos.go            package → repository from /var/lib/apt/lists (third-party detection)
    changelog.go        third-party changelogs: installed, and candidates via apt-get download + dpkg-deb
    system.go           os-release, distro-info EOL, kernel, reboot, needrestart/proc scan, livepatch, pro
internal/vulndb/
    vulndb.go           Open: sources for the host, DB, Advisory
    fetch.go            conditional download, size limits, atomic replace
    index.go            gob index cache
    debian.go           Debian Security Tracker JSON
    osv.go              Canonical OSV export (Ubuntu, including Pro)
    exploit.go          KEV, EPSS
    firstseen.go        first-seen publish dates for Debian CVEs
internal/risk/          policy engine → []Finding, CVE matching (cve.go), single-CVE status (cvecheck.go), third-party packages (thirdparty.go), changelog CVEs (changelog.go), escalation, ignore rules
internal/state/         state.json load/save/diff
internal/report/        model and formats: text, html (embedded html/template), json
internal/runx/          safe exec helper (argv only, timeout, LC_ALL=C, minimal env)
internal/httpx/         HTTP client: timeouts, size limits, user agent, retries
packaging/              nfpm.yaml, cron.d, systemd units, example config
testdata/               dpkg status files, apt-get -s outputs, vuln data fixtures, golden reports
```

---

## 14. Testing

- **Unit tests**: `debver` with Debian's own comparison test vectors; parsers fed real `dpkg/status` and `apt-get -s` outputs captured from every supported release; matching truth tables; risk escalation; state diffing.
- **Golden-file tests** for each report format.
- **`aptwatch cve`**: every status, the fix command, kernels and reboots, and the formats, on synthetic packages and advisories (never a real host's package list). First-seen dates: seeding, later dating, reseeding and the KEV fallback.
- **Report tests**: every format carries the same sections; hostile package text is escaped in HTML.
- **Integration tests**: run the binary in containers (`debian:12`, `debian:13`, `ubuntu:22.04`, `ubuntu:24.04`, `ubuntu:26.04`) with a deliberately old package pinned, and check that it reports the expected CVE and update.
- **Ubuntu Pro**: run on a real Pro-attached host (Pro can't be attached inside a throwaway container without using a licence seat) and compare the pending security updates with `pro security-status`. ESM and `fix requires Pro` matching is covered by unit tests on synthetic advisories. Real-host output is never kept as fixtures. Done 2026-10-22 on Ubuntu 24.04 with esm-apps and esm-infra enabled: the same 11 security updates at the same versions.
- **Debian**: checked by running reports on a real Debian host (done 2026-10-22). No `debsecan` comparison.

---

## 15. Milestones

| # | Deliverable | Done when |
|---|---|---|
| **M0** | Repo, Go module, `debver` package, safe exec helper | `debver` passes the Debian test vectors |
| **M1** | **End-to-end slice.** Collection (dpkg, apt simulation, reboot, kernel, EOL), basic findings and severities, state + diff, text report, `run` / `scan` commands | On the dev machine, `aptwatch run` lists pending security updates; a second run shows no new changes |
| **M2** | Vuln data: spike to confirm source formats and sizes, then cache, Debian tracker, OSV Ubuntu (including `Ubuntu:Pro:*`), KEV, EPSS, matching | Results agree with `pro security-status` on a Pro host; reports run on a Debian host (done) |
| **M3** | Third-party repository detection and changelog CVEs (done), full risk engine (escalation, restarts via needrestart), ignore rules, exit codes | Golden tests pass |
| **M4** | Report formats: `text`, `html`, `json` via `--format` / `report.format` (done; notifications removed) | `run --format html > page.html` gives a self-contained page; report tests pass |
| **M4a** | `aptwatch cve` (§3.1) and Debian first-seen publish dates (§6.2) (done) | `aptwatch cve CVE-ID` gives the right status and exit code on the dev machine; unit tests pass |
| **M4b** | Ignore rules (§7.3), `db update` / `db status`, `config check`, `--nagios` (done) | Unit tests pass; an ignore rule on the dev machine moves its finding to "Suppressed findings" |
| **M5** | `.deb` packaging, cron/systemd units, man page, README, CI | Install from `.deb` on a clean VM, edit config, get a report on the next run |
