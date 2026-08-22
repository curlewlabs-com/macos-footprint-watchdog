# macos-footprint-watchdog

Restart a macOS process whose physical memory footprint has run away, and prove
the replacement is healthy.

Some long-lived macOS daemons accumulate state without bound. They do not crash,
they do not log anything, and they do not get smaller - they just grow, for
days, until the host swaps so hard that everything else on it stalls. macOS has
no per-daemon memory limit to catch this: `launchd`'s resource-limit keys cannot
be applied to a system daemon whose job file lives on the signed system volume,
and Darwin ignores `RLIMIT_RSS` anyway.

This is a small root LaunchDaemon that watches one process, restarts it when its
footprint crosses a ceiling you set, and records exactly what it saw. Below the
ceiling it writes nothing at all.

- **No dependencies.** Stdlib Python 3 against `libSystem`. No pip, no brew,
  nothing vendored.
- **It checks once and exits.** `launchd` owns the cadence, so the watchdog
  cannot itself become the long-lived process that needs watching.
- **It refuses rather than guesses.** Exact executable-path matching, a
  re-verified target immediately before signalling, and a hard stop if more than
  one process matches.

## Use this for fseventsd

`fseventsd` is the case this was written for, and the one most people arrive
here with. It is the macOS file-system events daemon, and on a machine with
heavy, sustained file churn - a CI host, a build farm, a machine running many
working copies - it can accumulate path-matching state until its footprint is
tens of gigabytes. The observed failure held a **31.5 GiB** footprint with all
but a few MiB swapped out, after about 13 days of uptime, on a 12-core host
whose one-minute load average had reached 143. Restarting the daemon dropped it
to **4.2 MiB** and released roughly 19 GiB of swap immediately.

The daemon rebuilds whatever it actually needs, so a restart is cheap. What it
loses is event history that Spotlight and Time Machine consume, which they
handle by rescanning - so this is a deliberate call, not a free one, and it is
why the tool restarts on a measured threshold rather than on a timer.

```sh
sudo ./install.py --process fseventsd --ceiling 2GiB --interval 300
```

Nothing about the tool is specific to `fseventsd`; point `--process` at whatever
is misbehaving on your host.

## Install

Requires macOS and `/usr/bin/python3` (from the Command Line Tools -
`xcode-select --install` if it is missing). The installer checks for it.

```sh
git clone https://github.com/curlewlabs-com/macos-footprint-watchdog
cd macos-footprint-watchdog
sudo ./install.py --process fseventsd --ceiling 2GiB
```

That installs `/usr/local/sbin/footprint-watchdog` root-owned and mode 0755,
writes a LaunchDaemon to `/Library/LaunchDaemons`, and loads it. Re-running is
how you change settings - it rewrites the job and reloads it.

| Command | What it does |
| --- | --- |
| `sudo ./install.py --process P --ceiling C` | Install and load |
| `./install.py --process P --ceiling C --verify` | Check the installed files still match this checkout |
| `sudo ./install.py --process P --ceiling C --uninstall` | Unload and remove |

`--verify` needs no privileges and exits non-zero on any drift: a plist someone
edited in place, an executable that no longer matches the source, an install
that lost root ownership, a plist launchd would refuse, or an install directory
some other account controls. Run it from configuration management to catch a
host that quietly diverged.

Other options: `--interval` (seconds between checks, default 300), `--cooldown`
(minimum seconds between restarts, default 3600), `--log` (default
`/var/log/footprint-watchdog.log`), `--prefix`, and `--context-command`, which
records a count of some other process in the crossing record - useful for
capturing how much real work was in flight when the ceiling was crossed.

## Choosing a ceiling

There is no default: the right number depends on what the process does on your
host, and a wrong one either never fires or restarts something healthy. Measure
first.

```sh
# What is it right now? A ceiling of 1 byte forces a report.
sudo footprint-watchdog --process fseventsd --ceiling 1 --dry-run

# Does a candidate ceiling fire today? Silence means no.
sudo footprint-watchdog --process fseventsd --ceiling 2GiB --dry-run
```

`--dry-run` never signals anything, takes no lock, keeps no state, and is exempt
from the cooldown, so it is safe to run repeatedly while you settle on a number.

Pick a ceiling inside the gap between healthy and failed. For `fseventsd`,
healthy observations after a restart are single-digit MiB and failures are tens
of GiB, so anything from a few hundred MiB to a few GiB sits in a very wide gap;
2 GiB leaves enormous headroom over healthy while still firing long before the
host starts paging out real work. Set it below the point where your machine's
RAM would be under pressure from this process alone.

Every crossing record keeps the exact byte value that triggered it, so you can
adjust from your own evidence rather than from this paragraph.

## What it records

One line of JSON per event, and nothing at all on a healthy tick.

```json
{"event": "ceiling_crossed", "process": "fseventsd", "ceiling_bytes": 2147483648,
 "before": {"pid": 102, "footprint_bytes": 33822867456, "age_seconds": 1116000.0, ...},
 "host": {"load_average": [143.57, 217.12, 165.29], "swap": "total = 43008.00M used = 42489.00M ..."}}
{"event": "recovered", "process": "fseventsd",
 "before": {"pid": 102, "footprint_bytes": 33822867456, ...},
 "after": {"pid": 78708, "footprint_bytes": 4404019, "age_seconds": 1.2, ...}}
```

`before` and `after` are why the record exists: they show whether the restart
worked, and they are what you re-tune the ceiling from. The `host` block - load
average, swap, an optional process count - is context only. Those numbers
include every other process on the machine, so they can explain a crossing but
must never trigger one.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Below the ceiling, or restarted and the replacement is healthy |
| 2 | Usage error |
| 3 | Not root |
| 4 | Target not running, or unreadable |
| 5 | More than one process matched - refused to act |
| 6 | Above the ceiling but inside the cooldown - suppressed |
| 7 | Signalled, but no replacement appeared |
| 8 | Replacement appeared and is already above the ceiling |
| 9 | The state directory, or something above it, is not root-only |

Codes 6, 7 and 8 are the ones worth alerting on. Each means the failure is not
being fixed by restarting, which is a different problem from the one this tool
handles.

## Safety

It runs as root and sends signals, so the design is built around not doing that
to the wrong thing.

- **Exact matching, never substring.** `--process fsevents` does not match
  `fseventsd`. A basename must equal the target's basename; an absolute path
  must equal its resolved path.
- **pid 1 is never a target.**
- **Ambiguity is refused.** If two processes match, it reports and exits without
  signalling either. There is no way to know which one the ceiling described.
- **The target is re-proven immediately before the signal.** A pid measured a
  moment ago can exit and have its number reused; the identity is re-checked
  against the executable path rather than assumed to have held.
- **A cooldown, stamped before the outcome is known.** If the process is above
  the ceiling again within the cooldown, the tool reports and stops instead of
  restarting. The stamp is written before waiting for the replacement, so a
  watchdog that dies mid-recovery still cannot produce a restart loop.
- **Recovery is verified, not assumed.** It waits for a *different* pid running
  the same executable, then measures that one. "The old process is gone" is not
  accepted as success.
- **The install refuses a destination root does not solely control.** Every
  directory on the way to the installed executable, and to the LaunchDaemon,
  must be root-owned and not writable by anyone else. A mode check alone is not
  enough: a `0755` directory owned by some other account is still writable by
  that account, and a writable ancestor lets it swap the whole directory out.
  The watchdog applies the same rule to its state directory before creating
  predictable lock and state paths there as root.
- **`TERM`, not `KILL`, by default.**

Reporting a security issue: see [SECURITY.md](SECURITY.md). Please use private
vulnerability reporting rather than a public issue.

## How it measures

The signal is `phys_footprint` from the kernel's per-task ledger, read through
`proc_pid_rusage`. Three choices are worth explaining, because the obvious
alternatives are all wrong in ways that only show up during the failure.

**Not RSS.** As a runaway process drives the machine into swap, its own pages
are compressed and paged out - and RSS stops counting them. RSS therefore
*falls* as the failure gets worse. The observed `fseventsd` failure had
essentially its entire 31.5 GiB swapped out. Footprint counts compressed and
swapped pages; RSS is the one number guaranteed to under-report exactly when it
matters.

**Not `vmmap`.** `vmmap -summary` prints the same footprint value, but it walks
the process's entire VM map to do it, at a cost proportional to how many
allocations the process holds. Measured on a process holding 8 million
allocations: **22.3 seconds**. The `fseventsd` failure held roughly 92 million.
Spending minutes of CPU to take a measurement, on a host that is already
collapsing, is not a reasonable thing to do.

**Not `footprint(1)`.** It is fast (0.35s on that same process) but it prints a
value rounded to three significant figures, under a unit label that says `MB`
and means `MiB` - it renders 727,253,808 bytes as `694 MB`. The ledger read
gives an exact `uint64` of bytes with no parsing step, so the number in the log
is the number the decision was made on.

`--process` matches the **resolved executable path**, which is not always the
path you typed. `/usr/bin/python3` is a shim
that execs a framework binary, so a Python process reports as
`.../Python3.framework/.../Python`. If a match unexpectedly finds nothing, run
with `--ceiling 1 --dry-run` and look at the `path` field.

## Development

```sh
/usr/bin/python3 -m unittest discover -s test -v   # needs macOS and cc
npx pyright@1.1.409                                # strict, runs anywhere
```

The tests drive real processes through the real kernel ledger - compiling their
own target, allocating a known amount, signalling it, and watching a stand-in
supervisor replace it - rather than mocking the measurement. See the docstring
in `test/test_footprint_watchdog.py` for why, and `test/footprint_target.c` for
why the target has to be compiled per run.

CI runs both on `macos-15` and `macos-26`. The thing being read is a kernel
structure, so a change between major versions is the regression most worth
catching.

## License

MIT. See [LICENSE](LICENSE).
