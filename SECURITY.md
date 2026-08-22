# Security Policy

`macos-footprint-watchdog` runs as root on a schedule and sends signals to
processes, so "does it ever signal the wrong thing" is its security surface, not
a footnote to it. The design answers that with exact executable-path matching
(never substring), a structural refusal to ever target pid 1, a refusal to act
at all when more than one process matches, and a re-verification of the target's
identity immediately before the signal is sent - because a pid measured a moment
earlier can exit and have its number reused. The README "Safety" section and
[`docs/architecture.md`](docs/architecture.md) document the full reasoning.

The install path is part of that surface too. The executable is installed
root-owned and non-writable by other accounts, and installation is refused
outright unless every directory leading to it - and to the LaunchDaemon - is
root-owned and writable by nobody else. Checking the leaf's mode alone would
miss two shapes: a `0755` directory owned by another account, which that account
can still write, and a writable ancestor, which lets it replace the directory
entirely. The watchdog applies the same rule to its state directory before
creating lock and state files at predictable names there as root.

## Supported versions

This is a pre-1.0 project: fixes land on `main` and in the latest tagged
release. There are no maintained older release branches.

## Reporting a vulnerability

Report security issues **privately** - do not open a public issue. Use GitHub's
private vulnerability reporting: open the repository's **Security** tab and
choose **"Report a vulnerability"**, which opens a private advisory visible only
to the maintainers.

Helpful details to include:

- macOS version (`sw_vers -productVersion`) and Apple silicon vs Intel
- The exact command, and whether it ran as root or with `--dry-run`
- What you observed versus expected
- A minimal reproduction, if you have one

This is a small project, so responses are best-effort rather than on a fixed
SLA; we will acknowledge and work toward a fix as soon as we reasonably can.

## Scope

In scope: target identification and any path by which a signal could reach a
process other than the intended one; privilege boundaries in the installed
LaunchDaemon and the executable it runs; the state and lock files under the
state directory; and the `--verify` drift check failing to report real drift.

Out of scope: the consequences of restarting a daemon you chose to target. The
tool does what you configured it to do, and deciding that a given process is
safe to restart is the operator's call - see the README on what an `fseventsd`
restart costs.
