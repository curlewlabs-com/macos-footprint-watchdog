#!/usr/bin/python3
"""Install, verify, or remove the footprint-watchdog LaunchDaemon.

A system LaunchDaemon rather than a per-user agent or a job-level preflight step,
because the failure it handles is host-wide: several workloads share the daemon
being watched, and only root can read another process's ledger or signal a
system daemon.

`--verify` re-derives the executable and the plist from the tracked sources and
compares them byte for byte against what is installed, so a host that drifted --
someone edited the plist in place, or an install predates a change here - is a
non-zero exit rather than a silent difference between the repo and the machine.
"""

from __future__ import annotations

import argparse
import filecmp
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple, cast
from xml.parsers.expat import ExpatError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import footprint_watchdog as fw

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCE_NAME = "footprint_watchdog.py"
INSTALLED_NAME = "footprint-watchdog"
DEFAULT_PREFIX = "/usr/local/sbin"
DEFAULT_LOG = "/var/log/footprint-watchdog.log"
DEFAULT_INTERVAL_SECONDS = 300
LABEL_PREFIX = "com.curlewlabs.footprint-watchdog"
LAUNCH_DAEMONS = "/Library/LaunchDaemons"
# The interpreter the installed executable's shebang names. Verified at install
# time because a missing Command Line Tools install makes /usr/bin/python3 a stub
# that opens a GUI prompt - harmless in a terminal, a silently dead daemon here.
INTERPRETER = "/usr/bin/python3"
# What reading a job file can raise. ExpatError is here because it is NOT a
# ValueError: plistlib raises InvalidFileException (which is) for a binary plist
# it cannot make sense of, but malformed XML surfaces the parser's own error
# straight through, so catching ValueError alone lets that one escape.
PLIST_READ_ERRORS = (OSError, ValueError, ExpatError)


def ceiling_string(text: str) -> str:
    """Validate a ceiling at parse time, and keep the operator's spelling.

    The plist carries the string the operator wrote, so this returns it
    unchanged - but an unparseable one has to fail here rather than at the
    watchdog's first tick. Otherwise the install reports success and leaves the
    host with a job that can only fail, every interval, forever.
    """
    try:
        fw.parse_size(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))
    return text


def label_for(process: str) -> str:
    """The launchd label for a target.

    Keyed by footprint_watchdog.target_key so the job, the lock, and the
    cooldown stamp all name a target the same way. Sanitizing the raw spec here
    instead would let two different targets collide onto one label - and one
    install would then overwrite the other's job file.
    """
    return "%s.%s" % (LABEL_PREFIX, fw.target_key(process))


def plist_path_for(process: str) -> str:
    return os.path.join(LAUNCH_DAEMONS, label_for(process) + ".plist")


def build_plist(
    process: str,
    ceiling: str,
    interval: int,
    executable: str,
    log_path: str,
    cooldown: Optional[int],
    context_command: Optional[str],
    signal_name: Optional[str] = None,
) -> Dict[str, object]:
    arguments: List[str] = [executable, "--process", process, "--ceiling", ceiling]
    if cooldown is not None:
        arguments += ["--cooldown", str(cooldown)]
    if context_command is not None:
        arguments += ["--context-command", context_command]
    if signal_name is not None:
        arguments += ["--signal", signal_name]
    return {
        "Label": label_for(process),
        "ProgramArguments": arguments,
        # launchd owns the cadence; the executable checks once and exits. See the
        # module docstring in footprint_watchdog.py for why it is not a loop.
        "StartInterval": interval,
        "RunAtLoad": True,
        # Both streams to one file, appended. The quiet path writes nothing, so
        # this grows only when a ceiling is crossed and needs no rotation.
        "StandardOutPath": log_path,
        "StandardErrorPath": log_path,
        # The watchdog must never be the reason a host is busy: it yields to real
        # work, which costs nothing when the measurement takes microseconds.
        "ProcessType": "Background",
        "LowPriorityIO": True,
    }


def require_root() -> None:
    if os.geteuid() != 0:
        sys.stderr.write("must run as root (writes %s and %s)\n" % (DEFAULT_PREFIX, LAUNCH_DAEMONS))
        raise SystemExit(2)


def prepare_install_dir(directory: str) -> None:
    """Create the destination if absent, then refuse it if it is not root-only.

    /usr/local/sbin does not exist on a Mac that has never had anything
    installed there, so creating it is part of the job rather than a
    precondition to report.

    The installed file is executed by root every interval, so every directory on
    the way to it has to be root-owned and not writable by anyone else - which
    /usr/local often is not, on a Mac where a package manager took ownership.
    """
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o755)
    require_root_only_path(directory, "install into")


def require_root_only_log(log_path: str) -> None:
    """Refuse a log destination that is not root's alone to write.

    launchd opens this path as root on every run. Pointed at a directory some
    other account can write - `/tmp/watchdog.log` is the obvious spelling - that
    account can pre-place a symlink there and choose a file for root to append
    to. The directory has to be root-only, and an existing log has to be a plain
    root-owned file rather than a link.
    """
    directory = os.path.dirname(log_path) or "/"
    if not os.path.isdir(directory):
        sys.stderr.write(
            "refusing to log to %s: %s is not an existing directory, so launchd "
            "would silently discard every record\n" % (log_path, directory)
        )
        raise SystemExit(2)
    require_root_only_path(directory, "write a log into")
    if not os.path.lexists(log_path):
        return
    info = os.lstat(log_path)
    if stat.S_ISLNK(info.st_mode):
        sys.stderr.write("refusing to log to %s: it is a symlink\n" % log_path)
        raise SystemExit(2)
    if not stat.S_ISREG(info.st_mode):
        # A fifo or device here is not a redirect but it is still not a log:
        # root blocks on an unread fifo, taking the watchdog down with it.
        sys.stderr.write(
            "refusing to log to %s: not a regular file\n" % log_path
        )
        raise SystemExit(2)
    if info.st_uid != 0 or (info.st_mode & 0o022):
        sys.stderr.write(
            "refusing to log to %s: not root-owned, or writable by a non-root "
            "account\n" % log_path
        )
        raise SystemExit(2)


def require_root_only_path(path: str, action: str) -> None:
    unsafe = fw.unsafe_path_owners(path)
    if unsafe:
        sys.stderr.write(
            "refusing to %s %s: %s %s not root-owned, or writable by a non-root "
            "account, so that account chooses what root executes\n"
            % (action, path, ", ".join(unsafe), "is" if len(unsafe) == 1 else "are")
        )
        raise SystemExit(2)


def check_interpreter() -> None:
    try:
        subprocess.run([INTERPRETER, "-c", "import ctypes"], check=True, capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        sys.stderr.write(
            "%s is not usable (%s). Install the Command Line Tools: "
            "xcode-select --install\n" % (INTERPRETER, exc)
        )
        raise SystemExit(2)


def write_plist(target_path: str, contents: Dict[str, object], mode: int = 0o644) -> None:
    """Write a plist atomically, with the ownership and mode launchd requires.

    No explicit chown: launchd refuses a job file that is not root-owned or that
    is group/world writable, and both hold already - installation runs as root,
    so the temporary file is created root-owned, and the mode is set here. The
    temp-and-rename keeps a half-written plist from ever being visible under the
    real name, which launchd would read on its next scan.
    """
    directory = os.path.dirname(target_path)
    handle, temp_path = tempfile.mkstemp(dir=directory)
    with os.fdopen(handle, "wb") as stream:
        plistlib.dump(contents, stream, sort_keys=True)
    os.chmod(temp_path, mode)
    os.replace(temp_path, target_path)


def install_executable(source: str, destination: str) -> None:
    """Put the executable in place atomically.

    Copying onto the destination would truncate it and refill it in place, and
    launchd may exec that file at any moment - so a tick landing mid-copy runs a
    partial file, and a copy that fails leaves a permanently broken install.
    Writing a sibling and renaming means the destination is only ever the old
    file or the new one.

    No explicit chown, for the same reason write_plist has none: this runs as
    root, so the temporary file is created root-owned. (Copying onto an existing
    file would instead have preserved whatever owner it already had.)
    """
    handle, temp_path = tempfile.mkstemp(dir=os.path.dirname(destination))
    try:
        with os.fdopen(handle, "wb") as target:
            with open(source, "rb") as stream:
                shutil.copyfileobj(stream, target)
        os.chmod(temp_path, 0o755)
    except OSError:
        os.unlink(temp_path)
        raise
    os.replace(temp_path, destination)


def plists_referencing(executable: str) -> List[str]:
    """Installed job files whose ProgramArguments start with this executable."""
    referencing: List[str] = []
    try:
        names = sorted(os.listdir(LAUNCH_DAEMONS))
    except OSError:
        return referencing
    for name in names:
        if not name.startswith(LABEL_PREFIX) or not name.endswith(".plist"):
            continue
        path = os.path.join(LAUNCH_DAEMONS, name)
        try:
            with open(path, "rb") as stream:
                contents = plistlib.load(stream)
        except PLIST_READ_ERRORS:
            # An unreadable job file might still reference the executable, so
            # counting it as "no reference" would be the unsafe assumption.
            referencing.append(path)
            continue
        arguments = cast(object, contents.get("ProgramArguments"))
        if not isinstance(arguments, list) or not arguments:
            continue
        if str(cast(List[object], arguments)[0]) == executable:
            referencing.append(path)
    return referencing


def launchctl(arguments: List[str], check: bool) -> int:
    result = subprocess.run(["/bin/launchctl"] + arguments, capture_output=True, text=True, timeout=120)
    if result.returncode != 0 and check:
        sys.stderr.write("launchctl %s failed: %s\n" % (" ".join(arguments), result.stderr.strip()))
        raise SystemExit(1)
    return result.returncode


def do_install(args: argparse.Namespace) -> int:
    require_root()
    check_interpreter()
    prefix = str(args.prefix)
    prepare_install_dir(prefix)

    executable = os.path.join(prefix, INSTALLED_NAME)
    install_executable(os.path.join(REPO_ROOT, SOURCE_NAME), executable)
    print("installed %s" % executable)

    label = label_for(str(args.process))
    plist_path = plist_path_for(str(args.process))
    contents = build_plist(
        process=str(args.process),
        ceiling=str(args.ceiling),
        interval=int(args.interval),
        executable=executable,
        log_path=str(args.log),
        cooldown=args.cooldown,
        context_command=args.context_command,
        signal_name=args.signal,
    )
    require_root_only_path(LAUNCH_DAEMONS, "write a LaunchDaemon into")
    require_root_only_log(str(args.log))
    write_plist(plist_path, contents)
    print("installed %s" % plist_path)

    # bootout first so a re-run picks up a changed plist: bootstrap alone leaves
    # an already-loaded job running under its previous definition.
    launchctl(["bootout", "system/" + label], check=False)
    launchctl(["bootstrap", "system", plist_path], check=True)
    print("loaded %s" % label)
    print("\nWatch it with:  tail -f %s" % args.log)
    return 0


def verify_problems(args: argparse.Namespace) -> List[Tuple[str, str]]:
    """Every way the installed state differs from the tracked sources.

    Returns (code, detail) pairs. The code is the stable half - it is what a
    caller keys on and what stays constant while the human-readable detail
    changes - and an empty list means the host matches the repo.

    Separate from `do_verify` so the drift detection can be exercised without
    the privileges that writing a real install requires: a verification nobody
    can test is a verification nobody should trust.
    """
    executable = os.path.join(str(args.prefix), INSTALLED_NAME)
    plist_path = plist_path_for(str(args.process))
    problems: List[Tuple[str, str]] = []

    for component in fw.unsafe_path_owners(os.path.dirname(executable)):
        problems.append(("executable_dir_unsafe", component))
    for component in fw.unsafe_path_owners(LAUNCH_DAEMONS):
        problems.append(("launchdaemon_dir_unsafe", component))

    if not os.path.exists(executable):
        problems.append(("executable_missing", executable))
    else:
        try:
            matches = filecmp.cmp(
                os.path.join(REPO_ROOT, SOURCE_NAME), executable, shallow=False
            )
        except OSError as exc:
            # A verifier that raises where it promised a drift record turns a
            # config-management check into a traceback nobody can act on.
            problems.append(("executable_unreadable", "%s (%s)" % (executable, exc)))
            matches = True
        if not matches:
            problems.append(("executable_content_differs", executable))
        info = os.stat(executable)
        if info.st_uid != 0:
            problems.append(("executable_not_root_owned", executable))
        # Content, owner and write bits can all be correct on a file launchd
        # simply cannot run, and a watchdog that never runs reports nothing.
        if not info.st_mode & 0o111:
            problems.append(("executable_not_executable", executable))
        # Group- or world-writable means an account that is not root chooses
        # what root executes every interval.
        if info.st_mode & 0o022:
            problems.append(("executable_writable_by_non_root", executable))

    if not os.path.exists(plist_path):
        problems.append(("launchdaemon_missing", plist_path))
    else:
        info = os.stat(plist_path)
        # launchd itself refuses a job file that is not root-owned or that
        # others can write, so drift here does not merely differ from the
        # source - it stops the watchdog from loading at all.
        if info.st_uid != 0:
            problems.append(("launchdaemon_not_root_owned", plist_path))
        if info.st_mode & 0o022:
            problems.append(("launchdaemon_writable_by_non_root", plist_path))
        try:
            with open(plist_path, "rb") as stream:
                installed = cast(object, plistlib.load(stream))
        except PLIST_READ_ERRORS as exc:
            problems.append(("launchdaemon_unreadable", "%s (%s)" % (plist_path, exc)))
            return problems
        expected = build_plist(
            process=str(args.process),
            ceiling=str(args.ceiling),
            interval=int(args.interval),
            executable=executable,
            log_path=str(args.log),
            cooldown=args.cooldown,
            context_command=args.context_command,
            signal_name=args.signal,
        )
        if installed != expected:
            problems.append(("launchdaemon_differs", plist_path))
    return problems


def do_verify(args: argparse.Namespace) -> int:
    problems = verify_problems(args)
    for code, detail in problems:
        sys.stderr.write("DRIFT %s: %s\n" % (code, detail))
    if problems:
        return 1
    print("installed executable and LaunchDaemon match the tracked sources")
    return 0


def do_uninstall(args: argparse.Namespace) -> int:
    require_root()
    label = label_for(str(args.process))
    plist_path = plist_path_for(str(args.process))
    launchctl(["bootout", "system/" + label], check=False)
    if os.path.exists(plist_path):
        os.unlink(plist_path)
        print("removed %s" % plist_path)
    # One executable serves every watched target, so removing it because one
    # target went away would break the siblings that still point at it.
    executable = os.path.join(str(args.prefix), INSTALLED_NAME)
    still_used = plists_referencing(executable)
    if still_used:
        print(
            "kept %s - still referenced by %s"
            % (executable, ", ".join(os.path.basename(p) for p in still_used))
        )
    elif os.path.exists(executable):
        os.unlink(executable)
        print("removed %s" % executable)
    # The state directory is left behind: it holds the cooldown stamps that
    # record what this host did, and a reinstall should not discard them.
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Install, verify, or remove the footprint-watchdog LaunchDaemon.",
    )
    parser.add_argument("--process", required=True, help="Target executable name or absolute path.")
    parser.add_argument(
        "--ceiling",
        required=True,
        type=ceiling_string,
        help="Restart above this footprint (e.g. 2GiB).",
    )
    parser.add_argument(
        "--interval",
        type=fw.positive_int,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Seconds between checks (default: %(default)s).",
    )
    parser.add_argument(
        "--cooldown", type=fw.positive_int, help="Minimum seconds between restarts."
    )
    parser.add_argument("--context-command", help="Also count these processes in the crossing record.")
    # Exposed here, rather than left to a hand-edited plist, because --verify
    # reports a hand-edited plist as drift: every knob a real install needs has
    # to be reachable from the installer or the two rules contradict each other.
    parser.add_argument(
        "--signal",
        choices=("TERM", "KILL"),
        help="Signal to send (watchdog default: TERM).",
    )
    parser.add_argument("--log", default=DEFAULT_LOG, help="Log path (default: %(default)s).")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX, help="Install directory (default: %(default)s).")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--verify", action="store_true", help="Check installed files against the sources.")
    group.add_argument("--uninstall", action="store_true", help="Unload and remove.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.verify:
        return do_verify(args)
    if args.uninstall:
        return do_uninstall(args)
    return do_install(args)


if __name__ == "__main__":
    sys.exit(main())
