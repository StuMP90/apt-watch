# aptwatch

aptwatch checks a Debian or Ubuntu server for security updates it hasn't installed yet, and for CVEs that affect its installed packages. It is a single static Go binary. You run it once a day as root, usually from cron, and it writes a report to stdout as text, HTML or JSON. What happens to the report next is up to you: cron can mail it, you can redirect it to a file, or you can pipe it to a handler.

It answers three questions:

- **What is vulnerable?** Each installed package is matched against the distribution's own security data: the Debian Security Tracker on Debian, and Canonical's OSV export on Ubuntu, which includes Ubuntu Pro/ESM.
- **How urgent is it?** Severity starts from the distribution's priority. It is raised if CISA lists the CVE as known exploited (KEV), if its EPSS score is high, or if the fix has been waiting too long.
- **What should I do?** The report gives the exact `apt-get` command for each fix. It also covers pending reboots, services that need restarting, held packages, stale apt lists, and how close the OS release is to end of life.

Third-party repositories such as Sury PHP and Launchpad PPAs get special handling. These packages replace the distribution's own, so the distribution's data can't say whether they are fixed. aptwatch reads their changelogs instead (see [Third-party repositories](#third-party-repositories)).

The full design is in [SPEC.md](SPEC.md).

## Contents

- [Supported systems](#supported-systems)
- [Building](#building)
- [Installing](#installing)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Checking specific CVEs](#checking-specific-cves)
- [Report formats](#report-formats)
- [Scheduling](#scheduling)
- [Exit codes](#exit-codes)
- [Configuration](#configuration)
- [Ignoring findings](#ignoring-findings)
- [Vulnerability data](#vulnerability-data)
- [Third-party repositories](#third-party-repositories)
- [Files](#files)
- [Development](#development)
- [Not yet implemented](#not-yet-implemented)

## Supported systems

| Distribution | Releases |
|---|---|
| Debian | 12 (bookworm), 13 (trixie) |
| Ubuntu | 22.04, 24.04, 26.04 LTS, with or without Ubuntu Pro |

Hosts need outbound HTTPS access to the vulnerability data sources and to their apt mirrors.

## Building

You need Go 1.24 or later.

```sh
CGO_ENABLED=0 go build -trimpath -o aptwatch ./cmd/aptwatch
go test ./...
```

The binary is static, so you can build it once and copy it to every host of the same architecture.

## Installing

```sh
sudo install -o root -g root -m 0755 aptwatch /usr/sbin/aptwatch
sudo install -d -o root -g root -m 0755 /etc/aptwatch
sudo install -o root -g root -m 0600 /dev/null /etc/aptwatch/config.yaml
```

The config file is optional: without one, aptwatch uses its defaults and prints a warning. If you create one, root must own it and it must not be group- or world-writable, or aptwatch refuses to run as root. See [Configuration](#configuration) for its contents.

aptwatch creates its state and cache directories (`/var/lib/aptwatch`, `/var/cache/aptwatch`) the first time it runs.

## Quick start

```sh
sudo aptwatch scan                   # report on this host, text to the terminal
sudo aptwatch scan --format html > report.html
sudo aptwatch cve CVE-2026-109618    # is this one CVE fixed here?
```

`scan` reports without recording anything. `run` is the scheduled job: it also records what it found, so the next report can show what changed.

The first run downloads the vulnerability data, which takes longer. After that it uses the cache until the data is older than `vulndb.max_age`.

## Commands

| Command | What it does |
|---|---|
| `aptwatch run` | The daily job. Refreshes the apt lists if they are old, updates the vulnerability data, writes the report, saves state, and exits with a code that reflects what it found. |
| `aptwatch scan` | Writes the same report as `run` but saves no state, so "changes since last run" isn't shown. Useful interactively. |
| `aptwatch cve CVE-ID...` | Shows the status of one or more CVEs on this host. See [Checking specific CVEs](#checking-specific-cves). |
| `aptwatch db update [--force]` | Downloads any vulnerability data older than `vulndb.max_age` (every feed with `--force`) without checking the host, then shows the feed table. |
| `aptwatch db status [--json]` | Shows each vulnerability data feed from the cache: when it was last checked and changed, its size, and its last error. Downloads nothing. |
| `aptwatch config check` | Validates the config file and checks it is owned by root and not writable by group or others. Lists warnings and expired ignore rules. |
| `aptwatch state show` | Prints the saved state: the findings, when each was first seen, and the ones resolved recently. |
| `aptwatch state reset` | Deletes the saved state. Every finding then counts as new on the next run. |
| `aptwatch version` | Prints the version. |
| `aptwatch completion bash\|zsh\|fish` | Prints a shell completion script. |

**Global flags**

| Flag | Meaning |
|---|---|
| `-c`, `--config FILE` | Config file (default `/etc/aptwatch/config.yaml`) |
| `-q`, `--quiet` | Log only errors to stderr. The report still goes to stdout. |
| `--log-level LEVEL` | `debug`, `info` (default), `warn` or `error` |

**Flags for `run`, `scan` and `cve`**

| Flag | Meaning |
|---|---|
| `--format text\|html\|json` | Output format (default from `report.format`, else `text`) |
| `--nagios` | `run` and `scan` only: print one Nagios status line instead of the report (see [Exit codes](#exit-codes)) |
| `--no-refresh` | Use the cached apt lists and vulnerability data, and download nothing |
| `--dry-run` | `run` only: do everything except save state |

aptwatch needs root to refresh the apt lists. Without root it skips `apt-get update` and uses the lists it already has. If those are older than `apt.stale_after`, the report says so.

## Checking specific CVEs

When a CVE is in the news, `aptwatch cve` tells you whether this host is affected and, if it is, what to do. You can give several IDs at once, in any case.

### Example: the two critical PHP CVEs of October 2026

Here it checks two critical PHP CVEs on a Ubuntu 24.04 host that runs PHP from the Sury repository:

```console
$ aptwatch cve CVE-2026-109618 cve-2026-109619
worm25: 2 CVEs checked — 2 FIXED
================================

CVE-2026-109618  FIXED
  priority critical · published 2026-10-21 · EPSS 5%
  out-of-memory handling can interrupt PHP while internal request data is only partially initialized. Request cleanup may then treat the invalid data as valid.
  https://ubuntu.com/security/CVE-2026-109618
  Fixed in every affected installed package.

  Source  Installed                                           Fixed in  Status  Repository
  php7.4  1:7.4.33-31+0~20261021.121+ubuntu24.04~1.gbpe9c428  -         FIXED   packages.sury.org/php
  php8.2  8.2.35-1+0~20261021.94+ubuntu24.04~1.gbp8bff78      -         FIXED   packages.sury.org/php
  php8.3  8.3.36-1+0~20261021.88+ubuntu24.04~1.gbp250f7c      -         FIXED   packages.sury.org/php
  php8.4  8.4.27-1+0~20261021.57+ubuntu24.04~1.gbp7636b9      -         FIXED   packages.sury.org/php
  php7.4: named in the installed package's changelog
  php8.2: named in the installed package's changelog
  php8.3: named in the installed package's changelog
  php8.4: named in the installed package's changelog

CVE-2026-109619  FIXED
  priority critical · published 2026-10-21 · EPSS 6%
  request-owned internal state can survive after its backing memory has been freed. A later request handled by the same worker may use that stale state before normal initialization resets it.
  https://ubuntu.com/security/CVE-2026-109619
  Fixed in every affected installed package.

  Source  Installed                                           Fixed in  Status  Repository
  php7.4  1:7.4.33-31+0~20261021.121+ubuntu24.04~1.gbpe9c428  -         FIXED   packages.sury.org/php
  php8.2  8.2.35-1+0~20261021.94+ubuntu24.04~1.gbp8bff78      -         FIXED   packages.sury.org/php
  php8.3  8.3.36-1+0~20261021.88+ubuntu24.04~1.gbp250f7c      -         FIXED   packages.sury.org/php
  php8.4  8.4.27-1+0~20261021.57+ubuntu24.04~1.gbp7636b9      -         FIXED   packages.sury.org/php
  php7.4: named in the installed package's changelog
  php8.2: named in the installed package's changelog
  php8.3: named in the installed package's changelog
  php8.4: named in the installed package's changelog

Vulnerability data: osv-ubuntu, updated 1h ago (+KEV, EPSS)
$ echo $?
0
```

How to read it:

- **The heading line** is the overall verdict for each CVE. It is the worst status among the installed packages the CVE affects.
- **The priority, description and link** come from Ubuntu's security data. EPSS is the estimated probability that the CVE will be exploited in the next 30 days. A ★ would mark a CVE that CISA lists as known exploited.
- **The table** has one row per installed source package. These packages come from Sury rather than Ubuntu, so Ubuntu's own fixed version doesn't apply to them (hence "Fixed in" is `-`). aptwatch read each package's changelog instead and found the CVE named in the version that is installed.
- **Exit code 0** means nothing needs doing.

If the update had been available but not yet installed, the same command would show `FIX PENDING` with the new version and the command to install it:

```
CVE-2026-109618  FIX PENDING
  ...
  Source  Installed                    Fixed in                   Status       Repository
  php8.3  8.3.35-1+0~20260918.85+... → 8.3.36-1+0~20261021.88+...  FIX PENDING  packages.sury.org/php
  php8.3: named in the changelog of the pending update 8.3.36-1+0~20261021.88+...
    sudo apt-get install --only-upgrade php8.3-cli php8.3-fpm ...
```

It would then exit 1.

`--format html` gives the same information as a self-contained page, and `--format json` gives it in a form a script can read:

```sh
aptwatch cve CVE-2026-109618 --format json | jq -r '.checks[] | "\(.id) \(.status)"'
```

### Statuses

Statuses are listed from most urgent to least. A CVE's overall status is the most urgent status among its packages.

| Status | Meaning | Exit |
|---|---|---|
| `UNREACHABLE` | A fixed version exists, but apt can't install it. Check the apt sources, holds and pins. | 1 |
| `NEEDS PRO` | The fix is only in Ubuntu Pro (ESM). Attach Pro, or enable the esm sources. | 1 |
| `FIX PENDING` | An available update fixes it. The command to install it is shown. | 1 |
| `REBOOT PENDING` | The fix is installed but not running yet, for example a new kernel. | 1 |
| `NO FIX YET` | The distribution knows about the CVE but hasn't published a fix. | 1 |
| `UNCONFIRMED` | Third-party package: the distribution has fixed the CVE, but the third-party changelog doesn't mention it. | 1 |
| `UNKNOWN` | Can't tell. The ID isn't in the data or in any changelog that was read. It may be wrong, too new, rejected, or not relevant to this distribution. | 2 |
| `FIXED` | Every affected installed package has the fix. | 0 |
| `NOT AFFECTED` | None of the affected packages is installed. | 0 |

`aptwatch cve` exits with the highest code among the CVEs it checked. It exits 3 if an argument isn't a CVE ID:

```console
$ aptwatch cve not-a-cve
aptwatch: "not-a-cve" is not a CVE ID (CVE-YYYY-NNNN)
$ echo $?
3
```

## Report formats

`run` and `scan` write one report. In order, it contains:

1. **A summary line**, e.g. `web01: 2 CRITICAL, 1 HIGH — 5 updates pending (3 security) — reboot required`. The HTML page also uses it as its title, so it works as an email subject.
2. **Changes since the last run** (`run` only): new, escalated and resolved findings.
3. **Findings, by severity.** Each one shows the CVEs it covers, KEV (★) and EPSS, how long the fix has been pending, and the command that fixes it.
4. **Recent CVEs fixed in third-party packages.** These come from the changelogs, so you can see that, for example, last week's PHP CVEs are already patched.
5. **Pending updates**, security and other.
6. **System**: whether a reboot is needed, whether the running kernel is the newest one installed, services that need restarting, held packages, and the OS end-of-life date.
7. **Warnings**, such as stale data or a source that failed, with suggested commands.

| Format | Use it for |
|---|---|
| `text` (default) | The terminal, cron mail, logs |
| `html` | A self-contained page with inline CSS and no scripts, for a browser or an HTML email |
| `json` | Scripts, dashboards and monitoring. The document has a `schema` version number. |

The report always goes to stdout, so you choose where it ends up:

```sh
aptwatch run --format html > /var/www/status/$(hostname).html
aptwatch run --format json | /usr/local/bin/my-handler
aptwatch run --quiet | mail -s "aptwatch $(hostname)" admin@example.com
```

## Scheduling

aptwatch is meant to run once a day as root.

**cron** (`/etc/cron.d/aptwatch`). cron mails the output to `MAILTO` if the host can send mail:

```
MAILTO=admin@example.com
25 6 * * * root /usr/sbin/aptwatch run --quiet
```

To mail only when there is something to act on, wrap it in a script that tests the exit code. To keep a page instead of sending mail:

```
25 6 * * * root /usr/sbin/aptwatch run --quiet --format html > /var/www/status/report.html
```

**systemd timer.** The report goes to the journal unless you redirect it:

```ini
# /etc/systemd/system/aptwatch.service
[Unit]
Description=aptwatch security update check
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/aptwatch run --quiet
# Exit codes 1 and 2 report findings and warnings, not failures
SuccessExitStatus=1 2
```

```ini
# /etc/systemd/system/aptwatch.timer
[Unit]
Description=Daily aptwatch run

[Timer]
OnCalendar=*-*-* 06:25
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now aptwatch.timer
```

Only one aptwatch runs at a time. If another run holds the lock file (`/run/aptwatch.lock`), a second run exits at once with an error. aptwatch also waits up to `apt.lock_timeout` for apt's own lock, for example while unattended-upgrades is running.

## Exit codes

| Code | `run` / `scan` | `cve` |
|---|---|---|
| 0 | Nothing at or above `policy.exit_threshold` | Every CVE is fixed or doesn't apply |
| 1 | At least one finding at or above `policy.exit_threshold` (default `high`) | At least one CVE needs action |
| 2 | Warnings only (stale data, a source failed, etc.) | At least one CVE is unknown, or there were warnings |
| 3 | Fatal error: bad config, can't read the package database, etc. | Fatal error, or an argument isn't a CVE ID |

Findings suppressed by an [ignore rule](#ignoring-findings) don't count.

`db update`, `db status` and `config check` exit 2 when something needs attention (a feed failed or is stale, the config has warnings or expired ignore rules) and 3 on a fatal error.

### Nagios / Icinga

With `--nagios`, `run` and `scan` print a single line and use the Nagios exit codes:

| Code | Status | When |
|---|---|---|
| 0 | OK | No findings at Low or above, and no warnings |
| 1 | WARNING | Findings below `policy.exit_threshold`, or warnings |
| 2 | CRITICAL | Findings at or above `policy.exit_threshold` |
| 3 | UNKNOWN | Fatal error |

```console
$ sudo aptwatch scan --nagios --no-refresh
CRITICAL - web1: 1 HIGH, 6 MEDIUM, 5 LOW — 21 updates pending (11 security, 1 phased) — reboot required (26h)
$ echo $?
2
```

Use `scan --nagios` for an NRPE-style check, so the check doesn't change the saved state that the daily `run` compares against. It needs root (or sudo) to read the config, and `--no-refresh` keeps it from downloading data mid-check.

## Configuration

The config file is YAML. Every key is optional, and an unknown key is an error, so typos don't go unnoticed. These are the defaults:

```yaml
# /etc/aptwatch/config.yaml
host_label: ""                 # name shown in reports; default: the hostname
lock_file: /run/aptwatch.lock

apt:
  refresh_lists: true          # run apt-get update before checking...
  refresh_if_older_than: 6h    # ...if the lists are older than this
  lock_timeout: 10m            # how long to wait for apt's lock
  stale_after: 48h             # warn if the lists are older than this

vulndb:
  sources: [auto]              # auto: debian-tracker on Debian, osv-ubuntu on Ubuntu
  kev: true                    # CISA Known Exploited Vulnerabilities
  epss: true                   # FIRST exploit prediction scores
  max_age: 20h                 # download again if the cache is older than this
  stale_after: 72h             # warn if the data is older than this
  cache_dir: /var/cache/aptwatch
  max_size: 1GiB               # largest download accepted
  changelogs: true             # read third-party package changelogs

policy:
  exit_threshold: high         # lowest severity that gives exit code 1
  escalate_after: 7d           # raise a pending fix's severity after this long
  epss_bump: 0.5               # raise severity if EPSS is at least this
  reboot_escalate_after: 7d    # raise a pending reboot to high after this long
  eol_warn_before: 90d         # warn this long before the OS reaches end of life
  report_unfixed_cves: summary # none | summary | full: CVEs with no fix yet
  recent_cves: 90d             # how far back "recent CVEs" in third-party packages go
  report_third_party_gaps: true # flag third-party packages the distribution has fixed but the changelog doesn't mention

state:
  file: /var/lib/aptwatch/state.json
  keep_resolved: 30d           # how long resolved findings stay in the state

report:
  format: text                 # text | html | json
```

Durations are Go durations with a `d` (day) unit added, e.g. `36h`, `14d` or `1d12h`.

## Ignoring findings

An `ignore:` list in the config suppresses findings you have decided to accept. Every rule needs a `reason`, and should usually have an `until` date so it gets reviewed:

```yaml
ignore:
  - cve: CVE-2025-12345
    reason: "Vulnerable feature not compiled in; see ticket OPS-412"
    until: 2026-12-31            # last day the rule applies
  - package: "linux-image-*"     # shell glob
    kinds: [update-pending]      # only these finding kinds
    reason: "Kernel updates handled in the monthly window"
```

- A rule needs a `cve` or a `package` (or both). Leaving out `kinds` matches every kind.
- `package` is matched against the source package and each binary package of a finding.
- A finding that lists several CVEs, such as one security update that fixes three, is only suppressed by CVE rules when every one of its CVEs is covered. A new CVE in the same update brings it back.
- After its `until` day a rule expires and its findings count again.

Suppressed findings still appear in every report, under **Suppressed findings**, with the rule and its reason. They don't count in the summary line, the exit code, the Nagios status or "changes since last run". Expired rules are listed in the same section, and `aptwatch config check` warns about them:

```text
Suppressed findings (1)
  HIGH      CVE-2025-12345 in example 1.2-3: fixed by pending update 1.2-4
            ignored (CVE-2025-12345, until 2026-12-31): Vulnerable feature not compiled in; see ticket OPS-412
  ! ignore rule CVE-2024-0001 expired on 2026-10-01 (old reason): its findings count again; renew or remove it
```

Check the config after editing it:

```console
$ sudo aptwatch config check
/etc/aptwatch/config.yaml: OK
  2 ignore rules, 0 expired
```

### Severity

Each finding gets a severity: critical, high, medium, low or info. A CVE fix starts from the distribution's priority. Then:

- If CISA lists the CVE as known exploited, the finding becomes **critical**.
- If its EPSS score is at least `epss_bump`, it goes up one level.
- If the fix has been pending longer than `escalate_after`, it goes up one level.

The other findings have fixed defaults:

- a held security update: high;
- a pending reboot: medium, or high after `reboot_escalate_after`;
- the OS within `eol_warn_before` of end of life: medium, or high once it has reached end of life;
- a third-party repository that replaces distribution packages: low.

Severities only go up, never down. SPEC.md §7.2 has the full table.

## Vulnerability data

| Source | Used for |
|---|---|
| Debian Security Tracker (JSON) | CVEs and fixed versions on Debian |
| Canonical OSV export | CVEs, priorities and fixed versions on Ubuntu, including Pro/ESM |
| CISA KEV | Known exploited CVEs, and the date each was added |
| FIRST EPSS | Exploit probability scores |

aptwatch keeps the data in `vulndb.cache_dir` and downloads it again when it is older than `vulndb.max_age`. If a download fails, it uses the cached copy and warns (exit 2) once the copy is older than `vulndb.stale_after`.

`aptwatch db status` shows the state of each feed, and `aptwatch db update` refreshes them without checking the host:

```console
$ aptwatch db status
Vulnerability data in /var/cache/aptwatch for ubuntu 24.04

FEED               CHECKED                    CHANGED     SIZE     STATUS
osv-ubuntu.tar.xz  2026-10-22 15:00 (1h ago)  2026-10-22  50.2 MB  ok
kev.json           2026-10-22 15:00 (1h ago)  2026-10-22  1.7 MB   ok
epss.csv.gz        2026-10-22 15:00 (1h ago)  2026-10-22  2.6 MB   ok
```

A feed that failed to refresh shows `refresh failed DATE: error` and keeps being used. One that is older than `vulndb.stale_after` shows `stale`.

**Debian publish dates.** The Debian tracker gives no dates, so aptwatch dates each CVE by the day it first appeared in the data. These dates are kept in `<cache_dir>/debian-<release>-seen.json`. The CVEs that are already there on the first run get no date, so none of them count as "recent". From the second day on, new CVEs are dated properly. If a CVE is in KEV, the KEV date is used when there is nothing better. Ubuntu's data includes publish dates, so none of this applies to Ubuntu.

## Third-party repositories

Packages from Sury, PPAs, PGDG, NodeSource and similar repositories often replace the distribution's packages under the same names. The distribution's fixed version means nothing for them: Sury's `8.3.36-1+0~20261021.88+ubuntu24.04~1` can't be compared with Ubuntu's `8.3.6-0ubuntu0.24.04.5`.

For these packages aptwatch does the following:

1. It downloads the installed version and the candidate version with `apt-get download`. These are the same `.deb` files apt would fetch.
2. It extracts each changelog with `dpkg-deb`.
3. It looks for CVE IDs in the changelogs:
   - a CVE named in the installed version's changelog is **fixed**;
   - a CVE named only in the candidate's changelog is **fix pending**.
4. Where the distribution has fixed a CVE but the third-party changelog doesn't mention it, it reports **unconfirmed**. Some maintainers fix CVEs without naming them, so check the repository's announcements.

This is how the PHP example above knows the Sury packages are fixed. To turn changelog reading off, set `vulndb.changelogs: false`. The third-party packages are then reported as `UNKNOWN`.

The report also lists each third-party repository with its packages. Repositories that replace distribution packages are listed at low severity, so they don't go unnoticed.

## Files

| Path | Contents |
|---|---|
| `/usr/sbin/aptwatch` | The binary |
| `/etc/aptwatch/config.yaml` | Config (optional; root-owned, not group- or world-writable) |
| `/var/lib/aptwatch/state.json` | Findings from previous runs, used for "changes since last run" and escalation |
| `/var/cache/aptwatch/` | Vulnerability data, Debian first-seen dates, downloaded changelogs |
| `/run/aptwatch.lock` | Stops two runs overlapping |

aptwatch only reads the package database and runs `apt-get update` and `apt-get download`. It never installs, upgrades or removes anything.

## Development

`dev/config.yaml` keeps the lock, state and cache files in the working directory, so you can run aptwatch without root and without touching the system paths:

```sh
go build -o aptwatch ./cmd/aptwatch
./aptwatch scan --config dev/config.yaml
./aptwatch cve CVE-2026-109618 --config dev/config.yaml --no-refresh
```

The tests use only synthetic fixtures in `testdata/`. Don't copy a real `/var/lib/dpkg/status` there: it lists everything installed on the host.

```sh
gofmt -l . && go vet ./... && go test ./...
```

The code is laid out like this:

| Path | Contents |
|---|---|
| `cmd/aptwatch/` | The CLI |
| `internal/collect` | Installed packages, apt sources, reboot and kernel state, changelogs |
| `internal/vulndb` | Downloading, caching and parsing the vulnerability data |
| `internal/risk` | Matching, severities, escalation, CVE status |
| `internal/report` | The text, HTML and JSON output |
| `internal/state` | The state file |
| `internal/debver` | Comparing Debian version numbers |

## Not yet implemented

These are in SPEC.md but not built yet:

- **Packaging** (milestone M5): a `.deb`, systemd units and a man page. Until then, install by hand as described above.
