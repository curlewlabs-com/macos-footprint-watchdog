# Architecture

Why the tool is shaped the way it is. The README covers what it does; this
covers the decisions behind it, including the ones whose alternatives look
reasonable until you measure them.

## The failure being handled

A long-lived macOS daemon accumulates internal state without bound. It does not
crash and does not log. Its footprint grows over days until the host is paging
heavily, at which point every other workload on the machine slows down and the
cause is not obvious from any single process's CPU time.

The specific case this was built for was an `fseventsd` on a busy CI host: a
31.5 GiB physical footprint after about 13 days of uptime, with all but a few
MiB of it swapped out, on a 12-core machine whose one-minute load average had
reached 143 and whose 42 GiB of swap was essentially full. About 92 million live
small allocations, dominated by path strings. Restarting the daemon replaced it
with one holding 4.2 MiB and released roughly 19 GiB of swap immediately.

Two properties of that failure drive the whole design:

1. **The state is the problem, and it is discarded by a restart.** Nothing
   rebuilds it. This is why a restart is a real fix and not a papering-over.
2. **It recurs.** The accumulation starts again from zero at whatever rate the
   host's file churn dictates, so a one-time manual fix is not a fix.

## Why a LaunchDaemon and not a CI preflight step

The failure is host-wide. Several workloads share one system daemon, and only
root can read another process's ledger or signal a system daemon. A check that
ran inside one CI job would be running as the wrong user, at the wrong scope,
and only when that job happened to be scheduled.

## Why one-shot, with launchd owning the cadence

The tool checks once and exits; `StartInterval` in the job file decides how
often. A long-running watchdog process would be a second long-lived daemon on
the same host - the exact category of thing this exists to catch. A process that
exits after every check cannot leak, cannot wedge, and cannot drift out of sync
with its configuration.

The cost is process spawn per interval, which is negligible: the measurement
itself is a single syscall, and the quiet path does no I/O at all.

## Why `phys_footprint`, read from the ledger

The measurement is `ri_phys_footprint` from `proc_pid_rusage`, flavor 0. Three
alternatives were considered and rejected on measured grounds.

**RSS moves the wrong way.** As a runaway process pushes the machine into
swap, its own pages are compressed and paged out, and RSS stops counting them.
RSS therefore falls as the failure worsens. In the motivating failure nearly the
entire 31.5 GiB was swapped out - invisible to RSS. A threshold on RSS would be
least likely to fire exactly when it most needed to.

**`vmmap -summary` prints the right number at the wrong price.** It walks the
process's entire VM map, at a cost proportional to the number of allocations
held. Measured on a synthetic process holding 8 million allocations: 22.3
seconds. The motivating failure held roughly 92 million. Spending minutes of CPU
on a host that is already collapsing, in order to take a reading, is not a
reasonable trade - and it would have to be paid on the tick that matters most.

**`footprint(1)` is fast but lossy.** 0.35 seconds on that same process, but it
emits a value rounded to three significant figures under a unit label that reads
`MB` and means `MiB`: it renders 727,253,808 bytes as `694 MB`. Since a stated
goal is that the log preserve the exact crossing value so the ceiling can be
re-tuned from evidence, rounding away four significant figures at the point of
measurement defeats the purpose. Parsing it would also mean a text format Apple
can change, sitting directly underneath the threshold decision.

The ledger read returns a `uint64` of bytes with no parsing step, from the same
task-accounting source the other two report from.

**Flavor 0, specifically.** Every later `rusage_info` flavor appends fields;
flavor 0 already carries `ri_phys_footprint`, `ri_resident_size`, and
`ri_proc_start_abstime`. Asking for the oldest flavor that has what is needed
keeps the struct definition unambiguous across OS versions.

**The mach timebase conversion is not optional.** `ri_proc_start_abstime` is in
mach absolute units, whose ratio to nanoseconds is 1:1 on Intel but 125:3 on
Apple silicon. Skipping the conversion misreports process age by roughly 40x on
every ARM Mac - which matters because daemon age is one of the numbers the
crossing record exists to preserve.

## Host-wide numbers are context, never triggers

Swap use and load average are recorded in the crossing record and used for
nothing else. Both include every other process on the machine, so neither can
distinguish a runaway daemon from an honestly busy host - and both stay high
after the cold pages stop mattering. The governed quantity is one process's
footprint, and the trigger reads exactly that.

## Target identity

The tool runs as root and sends signals, so mistaking one process for another is
its worst possible failure. Identity is the executable path reported by
`proc_pidpath`, compared exactly:

- an absolute `--process` must equal the resolved path (the spec is passed
  through `realpath` first, or nothing under a symlinked prefix would ever
  match: the kernel reports `/private/tmp/x` for what the user typed as
  `/tmp/x`);
- otherwise the basename must be equal, never a substring.

pid 1 is excluded structurally rather than by trusting that no one will point a
ceiling at `launchd`.

**Ambiguity is refused.** If two processes match, neither is signalled. With
several matches there is no way to know which one the operator's ceiling
described, and picking one would be a guess with root privileges behind it.

**The target is re-proven immediately before the signal.** Between the
measurement and the `kill` the process can exit and the kernel can reuse its pid
for something unrelated. The path is re-checked at the last moment rather than
assumed to have held.

## Naming a target

The lock file, the cooldown stamp, and the launchd label all have to name the
same target as the matcher does, and the obvious approach - substitute unsafe
characters in the raw `--process` string - gets this wrong in both directions.

`/tmp/a/b` and `/tmp/a_b` both become `tmp_a_b`, so two different targets would
share one lock and one cooldown stamp, and each restart would suppress the
other's. Meanwhile `/tmp/x` and `/private/tmp/x` produce different strings for
one process, so a watchdog installed under each spelling would hold two
independent cooldowns and could signal a process the other had just restarted.

`target_key` therefore canonicalizes through the same `canonical_spec` the
matcher uses, then appends a digest of that canonical form. The readable prefix
is for whoever reads `launchctl list` or the state directory; the digest is what
makes the key unique.

## Paths root writes to, or executes from

Every directory on the way to the installed executable, to the LaunchDaemon, and
to the state directory must be root-owned and not writable by group or other.
Two shapes make a leaf-only mode check insufficient: a directory at `0755` owned
by some account other than root is writable by that account whatever its mode
says, and a writable ancestor lets that account replace the directory wholesale.
For the state directory the concrete attack is a symlink pre-placed at the lock
or state path, which would redirect a root write; for the executable and the
plist it is simply substituting what root runs every interval.

`unsafe_path_owners` walks from the resolved path up to the root and reports
every component that fails either test. A path that does not exist yet is judged
by the nearest ancestor that does, since that is what decides who can create it.

## The restart, and proving it worked

The signal is `TERM` by default; `KILL` is available but is not the default,
because the point is to let the supervisor replace the process cleanly.

Recovery means **exactly one process matches, and it is not the one signalled**.
The replacement is then measured, and only a replacement below the ceiling
counts as recovered.

Each half of that rules out a different wrong answer. Waiting merely for the old
process to disappear would call a healthy recovery a failure: launchd's respawn
is throttled, and in the motivating incident nothing matched for several seconds
after the signal. Accepting merely any different pid would do the opposite - a
target that ignores `TERM` can still be running when its supervisor starts a
second instance, and measuring the fresh one would report success while the
runaway is alive. The tick after that would find two matches and refuse to act
at all, so the watchdog would go quiet on a host it had already given up on.

## Cooldown, and why it is stamped early

If the process is above the ceiling again within the cooldown window, the tool
reports and stops. Without that, a failure that reproduces immediately - a bad
ceiling, or growth that is not what was diagnosed - becomes a restart loop
driven by the watchdog itself.

The stamp is written **before the signal**, which is the irreversible half.
Anything that ends this process in between - a crash, a SIGKILL, a failed
write - would otherwise leave the next tick free to signal again. If the stamp
cannot be written at all, no signal is sent: recording an attempt that then does
not happen costs one cooldown window, while the other order costs the
guarantee.

A corrupt state file reads as empty rather than raising. The cost of losing the
stamp is one extra restart; the cost of refusing to run is the failure this
exists to catch going unhandled.

## Concurrency

A tick can outlive its own interval while waiting for a respawn, so two ticks
can overlap. An exclusive `flock` on a per-target lock file means whichever tick
holds it is the one acting; the loser exits silently rather than sending a
second signal at a process that is already being replaced.

## Silence as a design property

Below the ceiling the tool writes nothing at all - not a heartbeat, not a
"checked, fine" line. A watchdog that logs every healthy tick trains its reader
to ignore the log. Every line in the log is an event that needed a human eye.

The `--verify` path is the counterpart: rather than logging continuously to
prove the install is intact, the install can be re-checked against the tracked
sources on demand, and exits non-zero on drift.
