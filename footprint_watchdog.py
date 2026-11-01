#!/usr/bin/python3
"""Restart a macOS process whose physical memory footprint has run away.

One tick: measure one process's `phys_footprint`, and if it is above a ceiling,
signal it and verify that its supervisor (launchd, for a system daemon) replaced
it with a healthy one. Below the ceiling it exits silently and writes nothing.

For `fseventsd` a tick also bounds the daemon's other unbounded growth: the
event history it persists on the Data volume. Above a history ceiling it asks
`fseventsd` to purge that history; `run_history_tick` says why, and
DEFAULT_HISTORY_CEILING why that is on by default.

Shape: this checks once and exits. launchd owns the cadence via `StartInterval`,
because a watchdog that is itself a long-lived process can become the thing that
needs watching - and the daemons this exists to catch are ones that grew
unbounded over days of uptime.

Metric: `phys_footprint` from the kernel's per-task ledger, not RSS. Under the
memory pressure a runaway daemon creates, its own pages get compressed and
swapped out, so RSS *falls* as the failure worsens. A badly runaway daemon ends
up with essentially all of its footprint swapped out - pages RSS does not count
at all. Footprint counts them, which is why it is the governed signal and RSS is
not.

Source: `proc_pid_rusage`, the same task-accounting ledger `vmmap` and
`footprint(1)` report from - read directly rather than by parsing either one.
`vmmap -summary` walks the whole VM map, which costs time proportional to the
allocation count: measured at 22.3s for a process holding 8M allocations, and a
daemon far enough gone to need restarting holds many times that. Spending
minutes of CPU to take a measurement is not an option on a host that is already
collapsing. `footprint(1)` is fast but prints a value rounded to three
significant figures ("694 MB" for 727,253,808 bytes) under a unit label that
reads as MB but means MiB. The ledger read here is a `uint64` of bytes with no
parsing step and no rounding, so the crossing value in the log is the exact
number the decision was made on.
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
import tempfile
import time
from typing import Callable, Dict, List, Optional, Sequence, Set, TextIO, Tuple, cast

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
EXIT_HISTORY_PURGE_FAILED = 10
EXIT_HISTORY_ABOVE_CEILING = 11

DEFAULT_STATE_DIR = "/var/db/footprint-watchdog"
DEFAULT_COOLDOWN_SECONDS = 3600
DEFAULT_RESPAWN_TIMEOUT_SECONDS = 60
DEFAULT_RESPAWN_POLL_SECONDS = 0.5
DEFAULT_HISTORY_VOLUME = "/System/Volumes/Data"
# Applied when the target is fseventsd and the operator names no history
# ceiling. A healthy history on a busy build machine measures in MiB; the ones
# that made fseventsd hold a core replaying them ran past ten GiB. A gibibyte
# sits far from both, which is what makes a default defensible here when the
# memory ceiling has none.
HISTORY_DEFAULT_PROCESS = "fseventsd"
DEFAULT_HISTORY_CEILING = "1GiB"

_PROC_ALL_PIDS = 1
_PROC_PIDPATHINFO_MAXSIZE = 4096
# proc_pid_rusage flavor 0. Every later flavor appends fields; v0 already carries
# the footprint and the process start time, so asking for the oldest one keeps
# the struct unambiguous across OS versions.
_RUSAGE_INFO_V0 = 0
# Doubling from the kernel's own count, so reaching the last one would need the
# process table to grow past several times its reported size mid-call.
_LIST_PIDS_ATTEMPTS = 6


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


def _load_core_services() -> ctypes.CDLL:
    lib = ctypes.CDLL("/System/Library/Frameworks/CoreServices.framework/CoreServices")
    lib.FSEventsGetLastEventIdForDeviceBeforeTime.argtypes = [ctypes.c_int32, ctypes.c_double]
    lib.FSEventsGetLastEventIdForDeviceBeforeTime.restype = ctypes.c_uint64
    lib.FSEventsPurgeEventsForDeviceUpToEventId.argtypes = [ctypes.c_int32, ctypes.c_uint64]
    lib.FSEventsPurgeEventsForDeviceUpToEventId.restype = ctypes.c_ubyte
    lib.FSEventsCopyUUIDForDevice.argtypes = [ctypes.c_int32]
    lib.FSEventsCopyUUIDForDevice.restype = ctypes.c_void_p
    return lib


def _load_core_foundation() -> ctypes.CDLL:
    lib = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    lib.CFUUIDCreateString.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.CFUUIDCreateString.restype = ctypes.c_void_p
    lib.CFStringGetCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
    lib.CFStringGetCString.restype = ctypes.c_ubyte
    lib.CFRelease.argtypes = [ctypes.c_void_p]
    lib.CFRelease.restype = None
    return lib


class _Statfs(ctypes.Structure):
    # struct statfs with 64-bit inodes, from <sys/mount.h>.
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def _load_statfs() -> Callable[..., int]:
    # <sys/cdefs.h> versions the 64-bit-inode layout as `statfs$INODE64` where
    # an older layout also exists (Intel), and as the bare name where it is the
    # only one (Apple silicon, which exports no suffixed symbol).
    try:
        function = getattr(_LIB, "statfs$INODE64")
    except AttributeError:
        function = _LIB.statfs
    function.argtypes = [ctypes.c_char_p, ctypes.POINTER(_Statfs)]
    function.restype = ctypes.c_int
    return cast(Callable[..., int], function)


_STATFS = _load_statfs()
_CORE_SERVICES = _load_core_services()
_CORE_FOUNDATION = _load_core_foundation()
_CF_STRING_ENCODING_UTF8 = 0x08000100


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


def positive_int(text: str) -> int:
    """An argparse type for a duration that must be greater than zero.

    Zero or negative disables the thing silently rather than erroring. A
    non-positive cooldown makes `cooldown_remaining` return 0.0 on every tick,
    which removes the restart-loop guard without saying so.
    """
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero, got %r" % text)
    return value


def positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero, got %r" % text)
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
    """Every pid on the host, or an error - never a partial list.

    proc_listpids fills the buffer it is given and reports how many bytes it
    wrote; it does not say it ran out of room. A read that exactly fills the
    buffer is therefore indistinguishable from a truncated one, so it is retried
    with a larger buffer until one comes back short. Silently returning a subset
    would be worse than failing: a missing process reads as "target absent", and
    a missing SECOND match reads as an unambiguous target - which is the one
    condition that permits a signal.
    """
    capacity = 0
    for _ in range(_LIST_PIDS_ATTEMPTS):
        needed: int = _LIB.proc_listpids(_PROC_ALL_PIDS, 0, None, 0)
        if needed <= 0:
            raise OSError(ctypes.get_errno(), "proc_listpids sizing failed")
        # Headroom over the kernel's own answer, since processes can appear
        # between the sizing call and the read.
        capacity = max(capacity * 2, needed // ctypes.sizeof(ctypes.c_int32) + 64)
        buffer = (ctypes.c_int32 * capacity)()
        written: int = _LIB.proc_listpids(
            _PROC_ALL_PIDS, 0, ctypes.byref(buffer), ctypes.sizeof(buffer)
        )
        if written <= 0:
            raise OSError(ctypes.get_errno(), "proc_listpids read failed")
        if written < ctypes.sizeof(buffer):
            count = written // ctypes.sizeof(ctypes.c_int32)
            return [int(buffer[i]) for i in range(count) if buffer[i] > 0]
    raise OSError("proc_listpids filled every buffer up to %d entries" % capacity)


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


def _ancestor_chain(path: str) -> List[str]:
    """`path` and every ancestor, starting at the nearest one that exists.

    A path that does not exist yet is governed by the nearest ancestor that
    does, since that is what decides who can create it.
    """
    current = path
    while not os.path.lexists(current):
        parent = os.path.dirname(current)
        if parent == current:
            return []
        current = parent
    chain: List[str] = []
    while True:
        chain.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            return chain
        current = parent


def unsafe_path_owners(path: str) -> List[str]:
    """Components of `path` that an account other than root could replace.

    Every directory on the way to a file root executes, or writes into, has to
    be root-owned and not writable by group or other. Checking only the leaf's
    write bits is not enough twice over: a leaf owned by a non-root account is
    writable by that account whatever its mode says, and a writable ancestor
    lets that account swap the whole directory out from under the leaf.

    Both the path as written and the path as resolved are audited, with lstat so
    a symlink is judged as itself rather than as its target. Resolving first and
    auditing only the result would clear `/tmp/link-to-a-root-owned-dir`, whose
    resolved form is beyond reproach while the link in /tmp stays replaceable by
    anyone - and it is the written path that root actually traverses.
    """
    absolute = os.path.abspath(path)
    problems: List[str] = []
    seen: Set[str] = set()
    for chain in (_ancestor_chain(absolute), _ancestor_chain(os.path.realpath(absolute))):
        for component in chain:
            if component in seen:
                continue
            seen.add(component)
            info = os.lstat(component)
            if info.st_uid != 0 or (info.st_mode & 0o022):
                problems.append(component)
    return problems


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
    """Replace the state file atomically, via a name nothing can predict.

    A fixed `.tmp` sibling would be a predictable path that root opens for
    writing. The state directory is verified root-only before any of this runs,
    so nothing else should be able to place a symlink there - but mkstemp costs
    nothing and removes the need for that argument to hold.
    """
    handle, temp_path = tempfile.mkstemp(dir=os.path.dirname(state_path))
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        json.dump(state, stream, sort_keys=True)
        stream.write("\n")
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


class HistorySample:
    """One volume's persisted FSEvents history at one instant.

    `uuid` names the event store. Every purge that drops anything gives the store
    a new one, which is what tells a client its saved event ID no longer applies,
    so the record carries it before and after.
    """

    def __init__(self, history_bytes: int, files: int, uuid: Optional[str]) -> None:
        self.history_bytes = history_bytes
        self.files = files
        self.uuid = uuid

    def as_record(self) -> Dict[str, object]:
        return {
            "history_bytes": self.history_bytes,
            "history_human": human_bytes(self.history_bytes),
            "files": self.files,
            "uuid": self.uuid,
        }


def resolve_history_ceiling(process: str, text: Optional[str]) -> Optional[int]:
    """The history ceiling a tick enforces, or None when it bounds no history.

    Unset means the default for fseventsd and off for anything else: no other
    daemon's history is this tool's to purge.
    """
    if text is None:
        if os.path.basename(canonical_spec(process)) != HISTORY_DEFAULT_PROCESS:
            return None
        text = DEFAULT_HISTORY_CEILING
    if text.strip().lower() == "off":
        return None
    return parse_size(text)


def mount_point(path: str) -> Optional[str]:
    """The mount point of the volume `path` is on, or None if statfs fails.

    Not `os.path.ismount`: it compares a path's device with its parent's, and
    on macOS firmlinks give `/System/Volumes` the Data volume's device, so the
    Data volume's own mount point reads as not a mount point.
    """
    info = _Statfs()
    if _STATFS(path.encode(), ctypes.byref(info)) != 0:
        return None
    return info.f_mntonname.decode()


def history_uuid(device: int) -> Optional[str]:
    reference = cast(Optional[int], _CORE_SERVICES.FSEventsCopyUUIDForDevice(device))
    if not reference:
        return None
    text = cast(Optional[int], _CORE_FOUNDATION.CFUUIDCreateString(None, reference))
    _CORE_FOUNDATION.CFRelease(reference)
    if not text:
        return None
    buffer = ctypes.create_string_buffer(64)
    converted = bool(_CORE_FOUNDATION.CFStringGetCString(text, buffer, len(buffer), _CF_STRING_ENCODING_UTF8))
    _CORE_FOUNDATION.CFRelease(text)
    return buffer.value.decode("ascii") if converted else None


def read_history(volume: str) -> Optional[HistorySample]:
    """The volume's persisted history, or None when it keeps none.

    A volume with no `.fseventsd`, or with Apple's per-volume `no_log` marker in
    it, has recording switched off by its owner; that is a configuration, not a
    history to bound, so it reads as nothing rather than as an error. A CI guest
    that turns its history off runs this same tick every interval.
    """
    directory = os.path.join(volume, ".fseventsd")
    try:
        entries = list(os.scandir(directory))
    except FileNotFoundError:
        return None
    if any(entry.name == "no_log" for entry in entries):
        return None
    total = 0
    files = 0
    for entry in entries:
        if entry.is_file(follow_symlinks=False):
            total += entry.stat(follow_symlinks=False).st_size
            files += 1
    return HistorySample(total, files, history_uuid(os.stat(volume).st_dev))


def purge_history(volume: str, now_epoch: float) -> Tuple[int, bool]:
    """Ask fseventsd to drop the volume's history through its newest event on
    disk. Returns that event ID (0 when there was none) and whether the purge
    call succeeded.

    Through the newest event rather than through some window: every purge gives
    the store a new UUID, and a client following Apple's FSEvents contract
    discards an event ID from an earlier UUID, so history kept behind a purge
    serves no such client. Purging all of it leaves the most room under the
    ceiling, and so the longest time until the next purge rotates the UUID
    again.

    Through the newest event on disk rather than the current event ID:
    fseventsd refused a purge to the current ID when that event was not yet in
    a journal file.
    """
    device = os.stat(volume).st_dev
    # FSEvents.h types this time as a CFAbsoluteTime, but fseventsd compares it
    # with Unix time: given a CFAbsoluteTime, even one in the future, it logs
    # "requested timestamp is prior to the earliest log file" and answers 0.
    event_id = int(_CORE_SERVICES.FSEventsGetLastEventIdForDeviceBeforeTime(device, now_epoch))
    if event_id == 0:
        return 0, False
    return event_id, bool(_CORE_SERVICES.FSEventsPurgeEventsForDeviceUpToEventId(device, event_id))


def run_history_tick(
    volume: str,
    ceiling: int,
    cooldown_seconds: float,
    state_path: Optional[str],
    dry_run: bool,
    now_fn: Callable[[], float],
    out: TextIO,
) -> int:
    """Bound the persisted FSEvents history of `volume`, the way run_tick bounds
    a process's footprint.

    fseventsd keeps every change on a volume, and on a machine with heavy file
    churn the history runs to days and gigabytes. That costs nothing until a
    client asks for events since an early ID, which makes fseventsd read the
    whole history back - and a client that does so on every
    launch, launched often, holds a core in fseventsd indefinitely. The no_log
    marker stops the growth but cannot be the fix on a machine with Time
    Machine: with it in effect on the Data volume, every backup fails in
    preflight for want of an event store.

    So a purge happens only above a measured ceiling, never on a timer: each one
    gives the store a new UUID, and every client that saved an event ID rescans
    instead of reading the history. The cooldown is stamped before the purge, as
    the restart's is before the signal, so a history that refills past the
    ceiling within it is reported rather than purged in a loop.
    """
    if mount_point(volume) != os.path.realpath(volume):
        # The purge acts on the device a path is on. A path that is not a mount
        # point would name whichever volume contains it, which for a typo is the
        # Data volume itself.
        emit({"event": "history_volume_not_mounted", "volume": volume}, out)
        return EXIT_USAGE
    try:
        sample = read_history(volume)
    except PermissionError as exc:
        emit({"event": "history_unreadable", "volume": volume, "reason": str(exc)}, out)
        return EXIT_NOT_ROOT
    if sample is None or sample.history_bytes <= ceiling:
        return EXIT_OK

    now_epoch = now_fn()
    state = read_state(state_path) if state_path is not None else {}
    last_purge = state.get("last_history_purge_epoch")
    remaining = cooldown_remaining(
        float(last_purge) if isinstance(last_purge, (int, float)) else None,
        now_epoch,
        cooldown_seconds,
    )
    if remaining > 0:
        emit(
            {
                "event": "history_cooldown_suppressed",
                "volume": volume,
                "history_ceiling_bytes": ceiling,
                "cooldown_remaining_seconds": round(remaining, 1),
                "before": sample.as_record(),
            },
            out,
        )
        return EXIT_COOLDOWN_SUPPRESSED

    emit(
        {
            "event": "history_ceiling_crossed",
            "volume": volume,
            "history_ceiling_bytes": ceiling,
            "history_ceiling_human": human_bytes(ceiling),
            "dry_run": dry_run,
            "before": sample.as_record(),
        },
        out,
    )
    if dry_run:
        return EXIT_OK

    if state_path is not None:
        state["last_history_purge_epoch"] = now_epoch
        state["last_history_purge_bytes"] = sample.history_bytes
        try:
            write_state(state_path, state)
        except OSError as exc:
            emit(
                {
                    "event": "cooldown_stamp_failed",
                    "path": state_path,
                    "reason": "%s; refusing to purge without a durable cooldown" % exc,
                },
                out,
            )
            return EXIT_UNSAFE_PATH

    event_id, purged = purge_history(volume, now_epoch)
    if not purged:
        emit(
            {
                "event": "history_purge_failed",
                "volume": volume,
                "event_id": hex(event_id),
                "reason": "no event on disk to purge through" if event_id == 0 else "fseventsd refused the purge",
            },
            out,
        )
        return EXIT_HISTORY_PURGE_FAILED

    after = read_history(volume)
    after_record = after.as_record() if after is not None else None
    if after is not None and after.history_bytes > ceiling:
        emit(
            {
                "event": "history_above_ceiling_after_purge",
                "volume": volume,
                "history_ceiling_bytes": ceiling,
                "purged_through_event_id": hex(event_id),
                "after": after_record,
            },
            out,
        )
        return EXIT_HISTORY_ABOVE_CEILING

    emit(
        {
            "event": "history_purged",
            "volume": volume,
            "history_ceiling_bytes": ceiling,
            "purged_through_event_id": hex(event_id),
            "before": sample.as_record(),
            "after": after_record,
        },
        out,
    )
    return EXIT_OK


def wait_for_replacement(
    spec: str,
    old_pid: int,
    timeout_seconds: float,
    now_fn: Callable[[], float],
    sleep_fn: Callable[[float], None],
    poll_seconds: float = DEFAULT_RESPAWN_POLL_SECONDS,
) -> Tuple[Optional[Tuple[int, str]], str]:
    """Wait for the supervisor to replace the target, unambiguously.

    Recovery means exactly one process matches and it is not the one signalled.
    The obvious "any different pid" check gets both halves wrong.

    Requiring the old pid to be gone: a target that ignores TERM can still be
    running when its supervisor starts a second instance. Measuring the fresh
    one and calling that recovered would report success while the runaway is
    alive - and the next tick would find two matches and refuse to act at all.

    Requiring exactly one: with several matches there is no way to say which one
    the ceiling now describes, which is the same reason the tick refuses an
    ambiguous target before signalling.

    Not "wait a fixed interval": launchd's respawn is throttled and has been
    observed to leave nothing matching for several seconds after the signal, so
    a check that gave up on the first empty poll would call a healthy recovery
    a failure. Returns (replacement, reason).
    """
    deadline = now_fn() + timeout_seconds
    while True:
        matches = find_targets(spec)
        survivors = [pid for pid, _ in matches if pid == old_pid]
        if not survivors and len(matches) == 1:
            return (matches[0], "replaced")
        if now_fn() >= deadline:
            if survivors:
                return (None, "signalled process is still running")
            if len(matches) > 1:
                return (None, "several processes match, so no single replacement")
            return (None, "nothing matches the target")
        sleep_fn(poll_seconds)


def first_failure(*codes: int) -> int:
    """The tick's exit code when it ran more than one check: the first that
    did not succeed, so neither check's failure hides behind the other's
    success."""
    for code in codes:
        if code != EXIT_OK:
            return code
    return EXIT_OK


# UTC, in the one form `log show --start` and `--end` accept with a zone, so a
# record's time can be pasted into them to read what the OS logged around it.
RECORD_TIME_FORMAT = "%Y-%m-%d %H:%M:%S+0000"


def emit(record: Dict[str, object], stream: TextIO) -> None:
    """One event, one line of JSON. Callers emit nothing on the quiet path."""
    stamped = dict(record)
    stamped["time"] = time.strftime(RECORD_TIME_FORMAT, time.gmtime())
    stream.write(json.dumps(stamped, sort_keys=True) + "\n")
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
        type=positive_int,
        default=DEFAULT_COOLDOWN_SECONDS,
        metavar="SECONDS",
        help="Minimum seconds between restarts (default: %(default)s).",
    )
    parser.add_argument(
        "--respawn-timeout",
        type=positive_float,
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
        "--history-ceiling",
        metavar="SIZE|off",
        help=(
            "Purge --history-volume's persisted FSEvents history above this size. "
            "Default: %s when the target is %s, off otherwise."
            % (DEFAULT_HISTORY_CEILING, HISTORY_DEFAULT_PROCESS)
        ),
    )
    parser.add_argument(
        "--history-volume",
        default=DEFAULT_HISTORY_VOLUME,
        metavar="PATH",
        help="Mount point whose history --history-ceiling bounds (default: %(default)s).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Measure and report a crossing, but never signal or purge anything.",
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

    try:
        history_ceiling = resolve_history_ceiling(
            str(args.process), cast(Optional[str], args.history_ceiling)
        )
    except ValueError as exc:
        parser.error(str(exc))

    spec = str(args.process)
    dry_run = bool(args.dry_run)
    history_volume = str(args.history_volume)

    # A dry run only reads, so it takes no lock, keeps no state, and is exempt
    # from both the root requirement and the cooldown. That is what makes it
    # usable for the job it exists for - watching a candidate ceiling against a
    # live process before arming anything - and running it can change nothing.
    if dry_run:
        code = run_tick(
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
        if history_ceiling is None:
            return code
        return first_failure(
            code,
            run_history_tick(
                volume=history_volume,
                ceiling=history_ceiling,
                cooldown_seconds=0.0,
                state_path=None,
                dry_run=True,
                now_fn=now_fn,
                out=out,
            ),
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
    # O_NOFOLLOW so the lock can never be a symlink root writes through. The
    # directory check above should already make that impossible; this makes the
    # open itself refuse rather than depending on it.
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(lock_fd)
        if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            return EXIT_OK
        raise
    try:
        code = run_tick(
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
        if history_ceiling is None:
            return code
        # After the process tick and independent of its outcome: a history
        # past its ceiling needs bounding whether or not the daemon itself
        # was found, measured, or restarted this tick.
        return first_failure(
            code,
            run_history_tick(
                volume=history_volume,
                ceiling=history_ceiling,
                cooldown_seconds=float(args.cooldown),
                state_path=state_path,
                dry_run=dry_run,
                now_fn=now_fn,
                out=out,
            ),
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

    # Re-resolve immediately before signalling, and require the same singleton
    # the tick required before measuring. Between the measurement above and this
    # line the target can exit and the kernel can hand its pid to something else
    # - signalling a recycled pid as root is the worst outcome this tool has - and
    # a second instance can appear, which is the ambiguity the tick already
    # refused to act under. Re-checking only that the measured pid survived
    # would uphold the first of those and quietly drop the second.
    current = find_targets(spec)
    if current != [(sample.pid, sample.path)]:
        if any(pid == sample.pid for pid, _ in current):
            emit(
                {
                    "event": "target_ambiguous",
                    "process": spec,
                    "pids": [pid for pid, _ in current],
                    "reason": "a second process appeared after measuring; refusing to signal",
                },
                out,
            )
            return EXIT_TARGET_AMBIGUOUS
        emit({"event": "target_changed_before_signal", "process": spec, "pid": sample.pid}, out)
        return EXIT_TARGET_ABSENT

    # Stamped BEFORE the signal, which is the irreversible half. Anything that
    # ends this process between the two - a crash, a SIGKILL, a failed write -
    # leaves the next tick free to signal again, which is the restart loop the
    # cooldown exists to prevent. Recording an attempt that then fails to happen
    # costs one cooldown window; the other order costs the guarantee.
    if state_path is not None:
        state["last_restart_epoch"] = now_epoch
        state["last_restart_pid"] = sample.pid
        state["last_restart_footprint_bytes"] = sample.footprint
        try:
            write_state(state_path, state)
        except OSError as exc:
            emit(
                {
                    "event": "cooldown_stamp_failed",
                    "path": state_path,
                    "reason": "%s; refusing to signal without a durable cooldown" % exc,
                },
                out,
            )
            return EXIT_UNSAFE_PATH

    signal_number = signal.SIGTERM if signal_name == "TERM" else signal.SIGKILL
    try:
        os.kill(sample.pid, signal_number)
    except OSError as exc:
        emit({"event": "signal_failed", "pid": sample.pid, "reason": str(exc)}, out)
        return EXIT_RESPAWN_FAILED

    replacement, reason = wait_for_replacement(
        spec, sample.pid, respawn_timeout, now_fn, sleep_fn
    )
    if replacement is None:
        emit(
            {
                "event": "recovery_unconfirmed",
                "process": spec,
                "signalled_pid": sample.pid,
                "waited_seconds": respawn_timeout,
                "reason": reason,
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
