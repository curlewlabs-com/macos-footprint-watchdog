#!/usr/bin/python3
"""Restart a macOS process whose physical memory footprint has run away.

One tick: measure one process's `phys_footprint`, and if it is above a ceiling,
signal it and verify that its supervisor (launchd, for a system daemon) replaced
it with a healthy one. Below the ceiling it exits silently and writes nothing.

Shape: this checks once and exits. launchd owns the cadence via `StartInterval`,
because a watchdog that is itself a long-lived process can become the thing that
needs watching - and the daemons this exists to catch are ones that grew
unbounded over days of uptime.

Metric: `phys_footprint` from the kernel's per-task ledger, not RSS. Under the
memory pressure a runaway daemon creates, its own pages get compressed and
swapped out, so RSS *falls* as the failure worsens. The observation that
motivated this tool held a 31.5 GiB footprint with all but a few MiB of it
swapped out - pages RSS does not count at all. Footprint counts them, which is
why it is the governed signal and RSS is not.

Source: `proc_pid_rusage`, the same task-accounting ledger `vmmap` and
`footprint(1)` report from - read directly rather than by parsing either one.
`vmmap -summary` walks the whole VM map, which costs time proportional to the
allocation count: measured at 22.3s for a process holding 8M allocations, and
the failure this was written for held ~92M. Spending minutes of CPU to take a
measurement is not an option on a host that is already collapsing. `footprint(1)`
is fast but prints a value rounded to three significant figures ("694 MB" for
727,253,808 bytes) under a unit label that reads as MB but means MiB. The ledger
read here is a `uint64` of bytes with no parsing step and no rounding, so the
crossing value in the log is the exact number the decision was made on.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional, Sequence, TextIO, Tuple, cast

# Exit codes are the operator's interface: launchd records them, and each names
# a distinct state so a log line is not needed to tell them apart.
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_ROOT = 3
EXIT_TARGET_ABSENT = 4
EXIT_TARGET_AMBIGUOUS = 5
EXIT_COOLDOWN_SUPPRESSED = 6
EXIT_RESPAWN_FAILED = 7
EXIT_REPLACEMENT_ABOVE_CEILING = 8
EXIT_UNSAFE_PATH = 9

DEFAULT_STATE_DIR = "/var/db/footprint-watchdog"
DEFAULT_COOLDOWN_SECONDS = 3600
DEFAULT_RESPAWN_TIMEOUT_SECONDS = 60
DEFAULT_RESPAWN_POLL_SECONDS = 0.5

_PROC_ALL_PIDS = 1
_PROC_PIDPATHINFO_MAXSIZE = 4096
# proc_pid_rusage flavor 0. Every later flavor appends fields; v0 already carries
# the footprint and the process start time, so asking for the oldest one keeps
# the struct unambiguous across OS versions.
_RUSAGE_INFO_V0 = 0


class _RUsageInfoV0(ctypes.Structure):
    """`struct rusage_info_v0` from <sys/resource.h>."""

    _fields_ = [
        ("ri_uuid", ctypes.c_uint8 * 16),
        ("ri_user_time", ctypes.c_uint64),
        ("ri_system_time", ctypes.c_uint64),
        ("ri_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_interrupt_wkups", ctypes.c_uint64),
        ("ri_pageins", ctypes.c_uint64),
        ("ri_wired_size", ctypes.c_uint64),
        ("ri_resident_size", ctypes.c_uint64),
        ("ri_phys_footprint", ctypes.c_uint64),
        ("ri_proc_start_abstime", ctypes.c_uint64),
        ("ri_proc_exit_abstime", ctypes.c_uint64),
    ]


class _MachTimebaseInfo(ctypes.Structure):
    """`struct mach_timebase_info` from <mach/mach_time.h>."""

    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


def _load_libsystem() -> ctypes.CDLL:
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    lib.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    lib.proc_pid_rusage.restype = ctypes.c_int
    lib.proc_listpids.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    lib.proc_listpids.restype = ctypes.c_int
    lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    lib.proc_pidpath.restype = ctypes.c_int
    lib.mach_absolute_time.argtypes = []
    lib.mach_absolute_time.restype = ctypes.c_uint64
    lib.mach_timebase_info.argtypes = [ctypes.c_void_p]
    lib.mach_timebase_info.restype = ctypes.c_int
    return lib


_LIB = _load_libsystem()


class Sample:
    """One process's ledger reading at one instant.

    `path` is the executable's absolute path, carried alongside the pid because
    every decision downstream re-checks it: a pid alone is not a stable identity
    once the process it named can exit.
    """

    def __init__(self, pid: int, path: str, footprint: int, resident: int, age_seconds: float) -> None:
        self.pid = pid
        self.path = path
        self.footprint = footprint
        self.resident = resident
        self.age_seconds = age_seconds

    def as_record(self) -> Dict[str, object]:
        return {
            "pid": self.pid,
            "path": self.path,
            "footprint_bytes": self.footprint,
            "footprint_human": human_bytes(self.footprint),
            "resident_bytes": self.resident,
            "age_seconds": round(self.age_seconds, 1),
        }


def human_bytes(value: int) -> str:
    """Render bytes for a human reader. Never the value a decision is made on."""
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            return "%.1f %s" % (size, unit) if unit != "B" else "%d B" % value
        size /= 1024.0
    return "%d B" % value


def parse_size(text: str) -> int:
    """Parse a byte size: a bare integer, or a number with a unit suffix.

    Accepts both `MiB` and `MB` spellings and treats both as powers of 1024 --
    the same conflation Apple's own tools print, and the safer reading for a
    ceiling, since a smaller-than-intended ceiling only restarts sooner.
    """
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMGT]i?B?|B)?\s*", text, re.IGNORECASE)
    if match is None:
        raise ValueError("not a byte size: %r (try 2GiB, 512MiB, or 2147483648)" % text)
    number = float(match.group(1))
    suffix = (match.group(2) or "B").upper().rstrip("B").rstrip("I")
    scale = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[suffix]
    value = int(number * scale)
    if value <= 0:
        raise ValueError("byte size must be positive: %r" % text)
    return value


def _mach_timebase() -> Tuple[int, int]:
    info = _MachTimebaseInfo()
    if _LIB.mach_timebase_info(ctypes.byref(info)) != 0:
        raise OSError("mach_timebase_info failed")
    return int(info.numer), int(info.denom)


def read_sample(pid: int, path: str) -> Optional[Sample]:
    """Read one pid's ledger, or None if it exited or is unreadable.

    Unreadable is the non-root case: `proc_pid_rusage` returns EPERM for a
    process this user does not own, which is why the tool requires root.
    """
    usage = _RUsageInfoV0()
    rc: int = _LIB.proc_pid_rusage(pid, _RUSAGE_INFO_V0, ctypes.byref(usage))
    if rc != 0:
        return None
    numer, denom = _mach_timebase()
    now_abs: int = _LIB.mach_absolute_time()
    elapsed_abs = now_abs - int(usage.ri_proc_start_abstime)
    # The timebase is not 1:1 on Apple silicon (125/3 for its 24MHz timer), so
    # skipping this conversion would misreport age by ~40x on every ARM Mac.
    age_seconds = (elapsed_abs * numer / denom) / 1e9 if elapsed_abs > 0 else 0.0
    return Sample(
        pid=pid,
        path=path,
        footprint=int(usage.ri_phys_footprint),
        resident=int(usage.ri_resident_size),
        age_seconds=age_seconds,
    )


def list_pids() -> List[int]:
    needed: int = _LIB.proc_listpids(_PROC_ALL_PIDS, 0, None, 0)
    if needed <= 0:
        raise OSError(ctypes.get_errno(), "proc_listpids sizing failed")
    # Processes can appear between the sizing call and the read, so ask for
    # headroom rather than exactly what the kernel just reported.
    capacity = needed // ctypes.sizeof(ctypes.c_int32) + 64
    buffer = (ctypes.c_int32 * capacity)()
    written: int = _LIB.proc_listpids(
        _PROC_ALL_PIDS, 0, ctypes.byref(buffer), ctypes.sizeof(buffer)
    )
    if written <= 0:
        raise OSError(ctypes.get_errno(), "proc_listpids read failed")
    count = written // ctypes.sizeof(ctypes.c_int32)
    return [int(buffer[i]) for i in range(count) if buffer[i] > 0]


def pid_path(pid: int) -> Optional[str]:
    buffer = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
    length: int = _LIB.proc_pidpath(pid, buffer, _PROC_PIDPATHINFO_MAXSIZE)
    if length <= 0:
        return None
    return buffer.value.decode("utf-8", "replace")


def canonical_spec(spec: str) -> str:
    """The single form of a target spec that identity decisions are made on.

    proc_pidpath reports resolved paths, so an absolute spec is resolved too or
    the comparison fails on any symlinked prefix: `/tmp/x` never matches, because
    the kernel reports the process as `/private/tmp/x`. Everything that names a
    target - the matcher, the lock, the cooldown stamp, the launchd label - goes
    through here, so two spellings of one process cannot be treated as two.
    """
    return os.path.realpath(spec) if spec.startswith("/") else spec


def target_key(spec: str) -> str:
    """A key naming one target, safe as a filename and as a launchd label.

    Two properties the obvious sanitize-to-underscores approach does not have.
    Distinct targets never collide: `/tmp/a/b` and `/tmp/a_b` both sanitize to
    `tmp_a_b`, which would give two processes one lock and one cooldown stamp.
    And aliases of one target never split: `/tmp/x` and `/private/tmp/x` are the
    same process, so a watchdog installed under each spelling would otherwise
    hold two independent cooldowns and signal it twice.

    The digest carries uniqueness; the readable prefix is there so an operator
    reading `launchctl list` or the state directory can tell what a key names.
    """
    canonical = canonical_spec(spec)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    readable = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(canonical))[:40]
    return "%s-%s" % (readable or "target", digest)


def unsafe_path_owners(path: str) -> List[str]:
    """Components of `path` that an account other than root could replace.

    Every directory on the way to a file root executes, or writes state into,
    has to be root-owned and not writable by group or other. Checking only the
    leaf's write bits is not enough twice over: a leaf owned by a non-root
    account is writable by that account whatever its mode says, and a writable
    ancestor lets that account swap the whole directory out from under the leaf.

    A path that does not exist yet is governed by the nearest ancestor that
    does, since that is what decides who can create it.
    """
    problems: List[str] = []
    current = os.path.realpath(path)
    while not os.path.exists(current):
        parent = os.path.dirname(current)
        if parent == current:
            return problems
        current = parent
    while True:
        info = os.stat(current)
        if info.st_uid != 0 or (info.st_mode & 0o022):
            problems.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            return problems
        current = parent


def find_targets(spec: str) -> List[Tuple[int, str]]:
    """Every running process matching `spec`, as (pid, executable path).

    Matching is EXACT - full path if `spec` is absolute, else basename. This is
    the tool's central safety property: it runs as root and sends signals, so a
    substring match ("fsevents" also matching some unrelated `fseventsd-probe`)
    is how a watchdog kills the wrong process with full privileges. An exact
    match that finds nothing is a loud, recoverable failure; a loose match that
    finds too much is not.

    pid 1 is never a target. launchd is nobody's runaway daemon, and signalling
    it is unrecoverable.
    """
    absolute = spec.startswith("/")
    # proc_pidpath reports the resolved path, so an absolute spec is resolved
    # too or the comparison fails on any symlinked prefix - `/tmp/x` never
    # matches, because the kernel reports the process as `/private/tmp/x`.
    if absolute:
        spec = os.path.realpath(spec)
    matches: List[Tuple[int, str]] = []
    for pid in list_pids():
        if pid <= 1:
            continue
        path = pid_path(pid)
        if path is None:
            continue
        if (path == spec) if absolute else (os.path.basename(path) == spec):
            matches.append((pid, path))
    return matches


def host_context(context_command: Optional[str]) -> Dict[str, object]:
    """Host-wide numbers that explain a crossing but never trigger one.

    Swap and load include every other process on the box, so they cannot tell a
    runaway daemon apart from an honestly busy machine - they belong in the
    record as context and nowhere in the decision.
    """
    context: Dict[str, object] = {}
    try:
        load1, load5, load15 = os.getloadavg()
        context["load_average"] = [round(load1, 2), round(load5, 2), round(load15, 2)]
    except OSError as exc:
        context["load_average_error"] = str(exc)

    try:
        swap = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "vm.swapusage"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        context["swap"] = swap.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        context["swap_error"] = str(exc)

    if context_command is not None:
        try:
            context["context_process_count"] = len(find_targets(context_command))
        except OSError as exc:
            context["context_process_error"] = str(exc)
    return context


def read_state(state_path: str) -> Dict[str, object]:
    try:
        with open(state_path, "r", encoding="utf-8") as handle:
            loaded = cast(object, json.load(handle))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        # A corrupt state file must not wedge the watchdog: the cost of losing
        # the cooldown stamp is one extra restart, and the cost of refusing to
        # run is the failure this exists to catch going unhandled.
        return {}
    if not isinstance(loaded, dict):
        return {}
    # Cast rather than validate field by field: every reader below re-checks the
    # type of the value it wants, so a wrong shape costs a default, not a crash.
    return cast(Dict[str, object], loaded)


def write_state(state_path: str, state: Dict[str, object]) -> None:
    temp_path = state_path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, sort_keys=True)
        handle.write("\n")
    os.chmod(temp_path, 0o600)
    os.replace(temp_path, state_path)


def cooldown_remaining(
    last_restart_epoch: Optional[float], now_epoch: float, cooldown_seconds: float
) -> float:
    """Seconds left before another restart is allowed; 0.0 when one is.

    `now_epoch` is a parameter rather than a `time.time()` call so the decision
    is testable without waiting, and so a clock that jumps backwards (a laptop
    resuming, an NTP step) is a value this function is handed rather than a
    hidden dependency. A negative elapsed time reads as "no time has passed",
    which holds the cooldown rather than releasing it early.
    """
    if last_restart_epoch is None:
        return 0.0
    elapsed = now_epoch - last_restart_epoch
    if elapsed < 0:
        return cooldown_seconds
    return max(0.0, cooldown_seconds - elapsed)


def wait_for_replacement(
    spec: str,
    old_pid: int,
    timeout_seconds: float,
    now_fn: Callable[[], float],
    sleep_fn: Callable[[float], None],
    poll_seconds: float = DEFAULT_RESPAWN_POLL_SECONDS,
) -> Optional[Tuple[int, str]]:
    """Wait for the supervisor to provide a DIFFERENT pid for the same target.

    Not "wait for the process to be gone", and not "wait a fixed interval":
    launchd's respawn is throttled and has been observed to leave nothing at all
    matching for several seconds after the signal, so a check that only looked
    for absence would call a healthy recovery a failure. A different pid running
    the same executable is the only thing that proves the replacement happened.
    """
    deadline = now_fn() + timeout_seconds
    while True:
        for pid, path in find_targets(spec):
            if pid != old_pid:
                return (pid, path)
        if now_fn() >= deadline:
            return None
        sleep_fn(poll_seconds)


def emit(record: Dict[str, object], stream: TextIO) -> None:
    """One event, one line of JSON. Callers emit nothing on the quiet path."""
    stream.write(json.dumps(record, sort_keys=True) + "\n")
    stream.flush()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="footprint-watchdog",
        description=(
            "Restart a macOS process whose physical memory footprint exceeds a "
            "ceiling, and verify its supervisor replaced it with a healthy one."
        ),
    )
    parser.add_argument(
        "--process",
        required=True,
        metavar="NAME|PATH",
        help=(
            "Target executable: a basename (fseventsd) or an absolute path. "
            "Matched exactly, never as a substring."
        ),
    )
    parser.add_argument(
        "--ceiling",
        required=True,
        metavar="SIZE",
        help=(
            "Restart above this physical footprint (2GiB, 512MiB, 2147483648). "
            "Required: there is no defensible default for someone else's daemon."
        ),
    )
    parser.add_argument(
        "--cooldown",
        type=int,
        default=DEFAULT_COOLDOWN_SECONDS,
        metavar="SECONDS",
        help="Minimum seconds between restarts (default: %(default)s).",
    )
    parser.add_argument(
        "--respawn-timeout",
        type=float,
        default=DEFAULT_RESPAWN_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help="How long to wait for a replacement pid (default: %(default)s).",
    )
    parser.add_argument(
        "--signal",
        choices=("TERM", "KILL"),
        default="TERM",
        help=(
            "Signal to send (default: %(default)s). TERM lets the target unwind; "
            "KILL is for a target that has stopped responding to TERM."
        ),
    )
    parser.add_argument(
        "--state-dir",
        default=DEFAULT_STATE_DIR,
        metavar="PATH",
        help="Where the cooldown stamp and lock live (default: %(default)s).",
    )
    parser.add_argument(
        "--context-command",
        metavar="NAME",
        help=(
            "Also count processes matching this name and record the count in the "
            "crossing record - e.g. the workload whose scheduling the runaway "
            "daemon is degrading."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Measure and report a crossing, but never signal anything.",
    )
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    now_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
    out: TextIO = sys.stdout,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ceiling = parse_size(str(args.ceiling))
    except ValueError as exc:
        parser.error(str(exc))

    spec = str(args.process)
    dry_run = bool(args.dry_run)

    # A dry run only reads, so it takes no lock, keeps no state, and is exempt
    # from both the root requirement and the cooldown. That is what makes it
    # usable for the job it exists for - watching a candidate ceiling against a
    # live process before arming anything - and running it can change nothing.
    if dry_run:
        return run_tick(
            spec=spec,
            ceiling=ceiling,
            cooldown_seconds=0.0,
            respawn_timeout=float(args.respawn_timeout),
            signal_name=str(args.signal),
            state_path=None,
            context_command=args.context_command,
            dry_run=True,
            now_fn=now_fn,
            sleep_fn=sleep_fn,
            out=out,
        )

    # Root is required to read another process's ledger (proc_pid_rusage returns
    # EPERM otherwise) and to signal a system daemon. Checked up front so the
    # failure names its cause instead of surfacing as an empty measurement.
    if os.geteuid() != 0:
        emit({"event": "not_root", "reason": "footprint read and signal both require root"}, out)
        return EXIT_NOT_ROOT

    state_dir = str(args.state_dir)
    try:
        os.makedirs(state_dir, mode=0o700, exist_ok=True)
    except OSError as exc:
        emit({"event": "state_dir_unusable", "path": state_dir, "reason": str(exc)}, out)
        return EXIT_USAGE

    unsafe = unsafe_path_owners(state_dir)
    if unsafe:
        # Root is about to create a lock and a state file at predictable names
        # in here. If any account other than root can write a component of this
        # path, it can pre-place a symlink at either name and choose where root
        # writes.
        emit(
            {
                "event": "state_dir_unsafe",
                "path": state_dir,
                "unsafe_components": unsafe,
                "reason": "not root-owned, or writable by a non-root account",
            },
            out,
        )
        return EXIT_UNSAFE_PATH

    key = target_key(spec)
    lock_path = os.path.join(state_dir, key + ".lock")
    state_path = os.path.join(state_dir, key + ".state.json")

    # A tick can outlive its interval while waiting for a respawn, so two ticks
    # can overlap. Whoever holds the lock is already handling this target;
    # the loser exits silently rather than sending a second signal.
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(lock_fd)
        if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            return EXIT_OK
        raise
    try:
        return run_tick(
            spec=spec,
            ceiling=ceiling,
            cooldown_seconds=float(args.cooldown),
            respawn_timeout=float(args.respawn_timeout),
            signal_name=str(args.signal),
            state_path=state_path,
            context_command=args.context_command,
            dry_run=dry_run,
            now_fn=now_fn,
            sleep_fn=sleep_fn,
            out=out,
        )
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def run_tick(
    spec: str,
    ceiling: int,
    cooldown_seconds: float,
    respawn_timeout: float,
    signal_name: str,
    state_path: Optional[str],
    context_command: Optional[str],
    dry_run: bool,
    now_fn: Callable[[], float],
    sleep_fn: Callable[[float], None],
    out: TextIO,
) -> int:
    matches = find_targets(spec)
    if not matches:
        emit({"event": "target_absent", "process": spec}, out)
        return EXIT_TARGET_ABSENT
    if len(matches) > 1:
        # Refusing beats guessing: with several matches there is no way to tell
        # which one the ceiling was measured against, and the tool signals as root.
        emit(
            {
                "event": "target_ambiguous",
                "process": spec,
                "pids": [pid for pid, _ in matches],
                "reason": "refusing to signal: narrow --process to an absolute path",
            },
            out,
        )
        return EXIT_TARGET_AMBIGUOUS

    pid, path = matches[0]
    sample = read_sample(pid, path)
    if sample is None:
        emit(
            {
                "event": "target_unreadable",
                "process": spec,
                "pid": pid,
                "reason": (
                    "proc_pid_rusage failed; a dry run as a non-root user cannot "
                    "read a process it does not own"
                ),
            },
            out,
        )
        return EXIT_TARGET_ABSENT

    # The quiet path: below the ceiling, write nothing at all. A watchdog that
    # logs every healthy tick trains its reader to ignore the log.
    if sample.footprint <= ceiling:
        return EXIT_OK

    now_epoch = now_fn()
    state = read_state(state_path) if state_path is not None else {}
    last_restart = state.get("last_restart_epoch")
    remaining = cooldown_remaining(
        float(last_restart) if isinstance(last_restart, (int, float)) else None,
        now_epoch,
        cooldown_seconds,
    )
    if remaining > 0:
        # Above the ceiling again inside the cooldown means the last restart did
        # not fix it. Restarting on every tick would turn one failure into a
        # signal loop, so this reports and stops.
        emit(
            {
                "event": "cooldown_suppressed",
                "process": spec,
                "ceiling_bytes": ceiling,
                "cooldown_remaining_seconds": round(remaining, 1),
                "before": sample.as_record(),
            },
            out,
        )
        return EXIT_COOLDOWN_SUPPRESSED

    before: Dict[str, object] = {
        "event": "ceiling_crossed",
        "process": spec,
        "ceiling_bytes": ceiling,
        "ceiling_human": human_bytes(ceiling),
        "dry_run": dry_run,
        "before": sample.as_record(),
        "host": host_context(context_command),
    }
    emit(before, out)
    if dry_run:
        return EXIT_OK

    # Re-resolve immediately before signalling. Between the measurement above and
    # this line the target can exit and the kernel can hand its pid to something
    # else; signalling a recycled pid as root is the worst outcome this tool has,
    # so the identity is re-proven rather than assumed to have held.
    confirmed = [p for p, resolved in find_targets(spec) if p == sample.pid and resolved == sample.path]
    if not confirmed:
        emit({"event": "target_changed_before_signal", "process": spec, "pid": sample.pid}, out)
        return EXIT_TARGET_ABSENT

    signal_number = signal.SIGTERM if signal_name == "TERM" else signal.SIGKILL
    try:
        os.kill(sample.pid, signal_number)
    except OSError as exc:
        emit({"event": "signal_failed", "pid": sample.pid, "reason": str(exc)}, out)
        return EXIT_RESPAWN_FAILED

    # Stamped BEFORE the respawn wait, not after: if this process dies while
    # waiting, the cooldown must still hold, or the next tick signals again.
    if state_path is not None:
        state["last_restart_epoch"] = now_epoch
        state["last_restart_pid"] = sample.pid
        state["last_restart_footprint_bytes"] = sample.footprint
        write_state(state_path, state)

    replacement = wait_for_replacement(
        spec, sample.pid, respawn_timeout, now_fn, sleep_fn
    )
    if replacement is None:
        emit(
            {
                "event": "respawn_failed",
                "process": spec,
                "signalled_pid": sample.pid,
                "waited_seconds": respawn_timeout,
                "reason": "no different pid appeared; supervisor may not restart this target",
            },
            out,
        )
        return EXIT_RESPAWN_FAILED

    new_pid, new_path = replacement
    new_sample = read_sample(new_pid, new_path)
    if new_sample is None:
        emit({"event": "replacement_unreadable", "pid": new_pid}, out)
        return EXIT_RESPAWN_FAILED

    if new_sample.footprint > ceiling:
        # A replacement that starts above the ceiling means the ceiling is wrong
        # or the growth is not what was diagnosed. Restarting again would not
        # help, so this reports loudly and lets the cooldown hold.
        emit(
            {
                "event": "replacement_above_ceiling",
                "process": spec,
                "ceiling_bytes": ceiling,
                "after": new_sample.as_record(),
            },
            out,
        )
        return EXIT_REPLACEMENT_ABOVE_CEILING

    emit(
        {
            "event": "recovered",
            "process": spec,
            "ceiling_bytes": ceiling,
            "before": sample.as_record(),
            "after": new_sample.as_record(),
            "host": host_context(context_command),
        },
        out,
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
