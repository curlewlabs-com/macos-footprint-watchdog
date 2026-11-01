# Architecture

Why the tool is shaped the way it is. The README covers what it does; this
covers the decisions behind it, including the ones whose alternatives look
reasonable until you measure them.

## The failure being handled

A long-lived macOS daemon accumulates internal state without bound. It does not
crash and does not log. Its footprint grows over days until the host is paging
heavily, at which point every other workload on the machine slows down and the
cause is not obvious from any single process's CPU time.

The specific case this was built for was an `fseventsd` on a busy CI host,
grown over days into tens of gigabytes of live small allocations dominated by
path strings, with nearly all of it swapped out and the machine's swap close to
full. Restarting the daemon returned it to a few MiB and released the swap
immediately.

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
entire footprint was swapped out - invisible to RSS. A threshold on RSS would be
least likely to fire exactly when it most needed to.

**`vmmap -summary` prints the right number at the wrong price.** It walks the
process's entire VM map, at a cost proportional to the number of allocations
held. Measured on a synthetic process holding 8 million allocations: 22.3
seconds. A daemon far enough gone to need restarting holds many times that.
Spending minutes of CPU on a host that is already collapsing, in order to take a
reading, is not a reasonable trade - and it would have to be paid on the tick
that matters most.

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

`unsafe_path_owners` reports every component that fails either test, walking the
path **as written** and the path **as resolved**, with `lstat` so a symlink is
judged as itself rather than as its target. Auditing only the resolved form
would clear `/tmp/link-to-a-root-owned-dir`: the resolution is beyond reproach
while the link in `/tmp` stays replaceable by anyone, and it is the written path
that root actually traverses. A path that does not exist yet is judged by the
nearest ancestor that does, since that is what decides who can create it.

## Installing over a running watchdog

launchd can exec the installed file at any moment, including while an install is
overwriting it, so the executable is written to a sibling and renamed into place
rather than copied onto the destination. A copy truncates first: a tick landing
mid-copy would run a partial file, and a copy that failed part-way would leave a
permanently broken install. With a rename, the destination is only ever the old
file or the new one.

One executable serves every watched target - the per-target state is the job
file, the lock, and the cooldown stamp. So uninstalling a target removes its job
file, and removes the executable only once no remaining job references it. A job
file that cannot be parsed counts as a reference, since guessing that it does
not is the guess that deletes a binary something still runs.

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

## The event history

`fseventsd` has a second unbounded growth that a restart does not address: the
change history it persists on the Data volume. Its cost is not the disk it
takes but the reads it invites. A client that asks for events since an early
ID makes `fseventsd` read the history back from that point, so a client that
does it on every launch, launched often, holds `fseventsd` near a full core for
as long as the history is long.

**Bounded by size, never by age or on a timer.** Every purge that drops anything
gives the volume's event store a new UUID, and a client that follows Apple's
FSEvents contract treats an event ID from an earlier UUID as lost history and
rescans. A timed purge would impose that on every such client on every healthy
machine, every interval. Above a measured ceiling only, the store changes
identity only when its size has become the problem. The cooldown is stamped
before the purge for the same reason it is stamped before a restart: a history
that refills past the ceiling within it is reported, not purged in a loop.

**Purged through the newest event on disk, not to a window.** History kept
behind a purge serves no client that honours the UUID change, so keeping a
window would cost purges sooner and buy nothing; purging all of it leaves the
most room, and so the longest time until the next UUID change. The newest event
on disk rather than the current event ID, because `fseventsd` refused a purge to
the current ID when that event was not yet in a journal file. That leaves the newest
journal file in place, which is why one purge can leave a small history above a
very small ceiling, and why exit code 11 exists.

**The lookup takes Unix time.** `FSEventsGetLastEventIdForDeviceBeforeTime` is
declared with a `CFAbsoluteTime` (seconds since 2001), but `fseventsd` compares
the value with Unix time. Given a `CFAbsoluteTime`, even one in the future, it
logs `requested timestamp is prior to the earliest log file` and answers 0.

**Not the `no_log` marker.** Apple's per-volume marker stops the history at the
source, and on a machine without Time Machine it is the simpler answer. On
macOS 26 with the marker in effect on the Data volume, every Time Machine backup
fails in preflight for want of an event store, so the marker cannot be the
general fix. A volume that carries it is the owner's choice, not a history to
bound: the tick reads it as history switched off and stays silent, which is
what lets a fleet that turns history off on its CI machines run the same
watchdog everywhere.

**A default, unlike the memory ceiling.** The memory ceiling has none because a
wrong one either never fires or restarts something healthy, and the right one
depends on the host. For the history the observed gap between healthy and
failing is wide enough - MiB against past ten GiB - that 1 GiB is far from both
on any machine, and leaving it off by default would leave every installed
`fseventsd` watchdog blind to the failure most likely to bring someone here.
Every other target gets no history check unless asked: another daemon's history
is not this tool's to purge.

**The volume must be a mount point.** The purge acts on the device a path is on,
so a path inside a volume names the whole volume. `os.path.ismount` cannot be
the check: it compares a path's device with its parent's, and firmlinks give
`/System/Volumes` the Data volume's device, so it reports the default volume as
not a mount point. `statfs` reports each path's actual mount point.

## Silence as a design property

Below the ceiling the tool writes nothing at all - not a heartbeat, not a
"checked, fine" line. A watchdog that logs every healthy tick trains its reader
to ignore the log. Every line in the log is an event that needed a human eye.

The `--verify` path is the counterpart: rather than logging continuously to
prove the install is intact, the install can be re-checked against the tracked
sources on demand, and exits non-zero on drift.
