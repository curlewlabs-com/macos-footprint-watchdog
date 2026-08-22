"""Tests for footprint_watchdog.

The integration cases drive real processes through the real kernel ledger rather
than a mocked measurement, because every bug worth catching here lives in the
boundary: what `proc_pidpath` actually reports, whether a signalled process is
actually replaced, whether the ledger actually reflects an allocation. A mocked `read_sample` would only
assert that the arithmetic in this file agrees with itself.

The target is compiled per run - see test/footprint_target.c for why nothing
already on the system can serve as one.
"""

from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Dict, List, Optional, Set, Tuple, cast

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import footprint_watchdog as fw  # noqa: E402

# Long enough that a target outlives the case driving it, short enough that a
# leaked process disappears on its own rather than lingering on a dev machine.
TARGET_LIFETIME_SECONDS = 90

# Practical INFINITE for this runner: every per-wait backstop here uses it, and
# none of them is meant to be reached. A ceiling picked to "fail fast" only
# converts runner contention into a flake, since a true hang fails the run at
# any ceiling while a healthy run under load can exceed a tight one.
#
# Sized off this runner rather than copied: the waits it bounds are a process
# spawn plus a 64 MiB memset, and a shell loop re-exec. Measured, all of the
# suite's healthy waits together account for under three seconds, so 60s is
# roughly three orders of magnitude of headroom on the slowest of them - and
# this suite runs one job per OS image, without the parallel contention that
# forces some runners higher.
INFINITE = 60.0

# The deliberate opposite, and not a backstop: a handful of cases assert what
# happens when the respawn wait EXPIRES, so for those the expiry is the
# behaviour under test rather than a hang guard. Short is the safe direction
# here - load can only make an expiry that is already expected arrive more
# surely - which is exactly why it must never be reused as a ceiling.
EXPIRING_RESPAWN_SECONDS = 1.0

_build_dir = ""
_target_bin = ""

# A pid that names no live process, for cases about what the old target's
# absence means. Above the default pid_max so it cannot collide with a real one.
_DEAD_PID = 999999


def setUpModule() -> None:
    global _build_dir, _target_bin
    _build_dir = tempfile.mkdtemp(prefix="footprint-watchdog-test.")
    source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "footprint_target.c")
    # realpath: the watchdog matches resolved paths, and mkdtemp hands back a
    # /var/folders path that is itself behind a symlink on macOS.
    _target_bin = os.path.realpath(os.path.join(_build_dir, "footprint-watchdog-testtarget"))
    subprocess.run(
        ["cc", "-O0", "-Wall", "-Wextra", "-o", _target_bin, source],
        check=True,
        capture_output=True,
    )


def tearDownModule() -> None:
    if _build_dir:
        subprocess.run(["rm", "-rf", _build_dir], check=False)


def _ps_pids() -> Set[int]:
    """Every pid ps can see, as an independent check on the ctypes listing."""
    listing = subprocess.run(
        ["/bin/ps", "-A", "-o", "pid="], capture_output=True, text=True, check=True
    )
    return {int(line) for line in listing.stdout.split()}


def _wait_for_ready(process: "subprocess.Popen[str]") -> None:
    """Block until the target reports its allocation is dirtied and resident."""
    assert process.stderr is not None
    deadline = time.time() + INFINITE
    while time.time() < deadline:
        line = process.stderr.readline()
        if "ready" in line:
            return
        if process.poll() is not None:
            raise AssertionError("target exited before signalling ready")
    raise AssertionError("target did not signal ready within %.0fs" % INFINITE)


class TargetProcess:
    """A single target process, optionally under a respawning supervisor.

    The supervisor is the test's stand-in for launchd: a shell loop that re-execs
    the target when it exits, which is the only thing that makes a "was it
    replaced?" assertion meaningful.
    """

    def __init__(self, mib: int, respawn_mib: Optional[int] = None) -> None:
        self.respawning = respawn_mib is not None
        if self.respawning:
            script = '"$1" "$2" "$4"; while :; do "$1" "$3" "$4"; done'
            command = [
                "/bin/sh",
                "-c",
                script,
                "sh",
                _target_bin,
                str(mib),
                str(respawn_mib),
                str(TARGET_LIFETIME_SECONDS),
            ]
        else:
            command = [_target_bin, str(mib), str(TARGET_LIFETIME_SECONDS)]
        # Its own session so cleanup can take down the supervisor and whichever
        # target it currently owns in one call.
        self.process = subprocess.Popen(
            command,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        _wait_for_ready(self.process)

    def pids(self) -> List[int]:
        return [pid for pid, _ in fw.find_targets(_target_bin)]

    def close(self) -> None:
        try:
            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
        except OSError:
            pass
        if self.process.stderr is not None:
            self.process.stderr.close()
        self.process.wait(timeout=INFINITE)


class ParseSizeTest(unittest.TestCase):
    def test_accepts_bare_bytes_and_unit_suffixes(self) -> None:
        self.assertEqual(fw.parse_size("2147483648"), 2147483648)
        self.assertEqual(fw.parse_size("1KiB"), 1024)
        self.assertEqual(fw.parse_size("512MiB"), 512 * 1024 ** 2)
        self.assertEqual(fw.parse_size("2GiB"), 2 * 1024 ** 3)
        self.assertEqual(fw.parse_size("1TiB"), 1024 ** 4)

    def test_mb_and_mib_mean_the_same_thing(self) -> None:
        # Apple's own tools print "MB" for what is really MiB (footprint(1)
        # renders 727,253,808 bytes as "694 MB"), so a ceiling written either way
        # has to mean the same thing or the operator's intent is silently scaled.
        self.assertEqual(fw.parse_size("512MB"), fw.parse_size("512MiB"))
        self.assertEqual(fw.parse_size("2gb"), fw.parse_size("2GiB"))

    def test_rejects_values_that_would_arm_a_meaningless_ceiling(self) -> None:
        for bad in ("", "GiB", "-1", "0", "2 potatoes", "1e9"):
            with self.assertRaises(ValueError, msg=bad):
                fw.parse_size(bad)


class HumanBytesTest(unittest.TestCase):
    def test_scales_to_the_largest_fitting_unit(self) -> None:
        self.assertEqual(fw.human_bytes(512), "512 B")
        self.assertEqual(fw.human_bytes(1024), "1.0 KiB")
        self.assertEqual(fw.human_bytes(68190568), "65.0 MiB")
        self.assertEqual(fw.human_bytes(33 * 1024 ** 3), "33.0 GiB")


class CooldownTest(unittest.TestCase):
    def test_no_prior_restart_allows_one(self) -> None:
        self.assertEqual(fw.cooldown_remaining(None, 1000.0, 3600.0), 0.0)

    def test_inside_the_window_holds(self) -> None:
        self.assertEqual(fw.cooldown_remaining(1000.0, 1600.0, 3600.0), 3000.0)

    def test_past_the_window_releases(self) -> None:
        self.assertEqual(fw.cooldown_remaining(1000.0, 5000.0, 3600.0), 0.0)

    def test_clock_moving_backwards_holds_rather_than_releases(self) -> None:
        # An NTP step or a resumed laptop can place "now" before the stamp. The
        # safe reading is that no time has passed: releasing early would let a
        # reproducing failure become a restart loop, which is the one outcome
        # the cooldown exists to prevent.
        self.assertEqual(fw.cooldown_remaining(5000.0, 1000.0, 3600.0), 3600.0)


class StateFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.mkdtemp(prefix="footprint-watchdog-state.")
        self.path = os.path.join(self.directory, "target.state.json")

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", self.directory], check=False)

    def test_missing_state_reads_as_empty(self) -> None:
        self.assertEqual(fw.read_state(self.path), {})

    def test_corrupt_state_reads_as_empty_rather_than_raising(self) -> None:
        # A truncated write (power loss mid-tick) must cost one extra restart,
        # not stop the watchdog from ever running again.
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        self.assertEqual(fw.read_state(self.path), {})

    def test_written_state_is_private_to_root(self) -> None:
        fw.write_state(self.path, {"last_restart_epoch": 123.0})
        self.assertEqual(fw.read_state(self.path), {"last_restart_epoch": 123.0})
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)


class FindTargetsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetProcess(mib=8)
        self.addCleanup(self.target.close)

    def test_matches_by_absolute_path_and_by_basename(self) -> None:
        by_path = fw.find_targets(_target_bin)
        by_name = fw.find_targets(os.path.basename(_target_bin))
        self.assertEqual(len(by_path), 1)
        self.assertIn(by_path[0][0], [pid for pid, _ in by_name])

    def test_does_not_match_a_prefix_of_the_name(self) -> None:
        # The tool runs as root and sends signals, so a substring match is how it
        # would kill an unrelated process whose name merely starts the same way.
        prefix = os.path.basename(_target_bin)[:-4]
        self.assertEqual(fw.find_targets(prefix), [])

    def test_resolves_a_symlinked_spec(self) -> None:
        # proc_pidpath reports resolved paths, so `/tmp/x` would never match a
        # process the kernel calls `/private/tmp/x` without this.
        link_dir = tempfile.mkdtemp(prefix="footprint-watchdog-link.")
        self.addCleanup(subprocess.run, ["rm", "-rf", link_dir], check=False)
        link = os.path.join(link_dir, "link-to-build")
        os.symlink(os.path.dirname(_target_bin), link)
        via_link = os.path.join(link, os.path.basename(_target_bin))
        self.assertEqual(len(fw.find_targets(via_link)), 1)

    def test_never_returns_launchd(self) -> None:
        # Signalling pid 1 is unrecoverable, so it is excluded structurally
        # rather than by trusting no ceiling will ever be set against it.
        self.assertEqual([pid for pid, _ in fw.find_targets("/sbin/launchd") if pid == 1], [])


class TimingArgumentTest(unittest.TestCase):
    """Durations that silently disable a guard when they are not positive."""

    def test_a_non_positive_cooldown_is_rejected(self) -> None:
        # cooldown_remaining returns 0.0 for any non-positive window, so this
        # would turn the restart-loop guard off without reporting anything.
        self.assertEqual(fw.cooldown_remaining(1000.0, 1000.0, -1.0), 0.0)
        for bad in ("0", "-1"):
            with self.assertRaises(SystemExit):
                fw.build_parser().parse_args(
                    ["--process", "x", "--ceiling", "1GiB", "--cooldown", bad]
                )

    def test_a_non_positive_respawn_timeout_is_rejected(self) -> None:
        for bad in ("0", "-0.5"):
            with self.assertRaises(SystemExit):
                fw.build_parser().parse_args(
                    ["--process", "x", "--ceiling", "1GiB", "--respawn-timeout", bad]
                )

    def test_positive_values_still_parse(self) -> None:
        parsed = fw.build_parser().parse_args(
            ["--process", "x", "--ceiling", "1GiB", "--cooldown", "60",
             "--respawn-timeout", "0.5"]
        )
        self.assertEqual(parsed.cooldown, 60)
        self.assertEqual(parsed.respawn_timeout, 0.5)


class TargetKeyTest(unittest.TestCase):
    def test_specs_that_sanitize_alike_do_not_collide(self) -> None:
        # Both of these become "tmp_a_b" if the key is just a character
        # substitution, which would hand two different targets one lock file and
        # one cooldown stamp - so restarting either would suppress the other.
        self.assertNotEqual(fw.target_key("/tmp/a/b"), fw.target_key("/tmp/a_b"))

    def test_aliases_of_one_target_share_a_key(self) -> None:
        # /tmp is a symlink to /private/tmp, so these name one process. Two keys
        # would mean two installs with independent cooldowns, each free to
        # signal a process the other had just restarted.
        self.assertEqual(fw.target_key("/tmp/x"), fw.target_key("/private/tmp/x"))

    def test_key_is_usable_as_a_filename_and_a_launchd_label(self) -> None:
        key = fw.target_key("/System/Library/Frameworks/Foo.framework/fseventsd")
        self.assertNotIn("/", key)
        self.assertRegex(key, r"^[A-Za-z0-9_.-]+$")

    def test_key_still_names_its_target_readably(self) -> None:
        self.assertTrue(fw.target_key("fseventsd").startswith("fseventsd-"))


class ListPidsTest(unittest.TestCase):
    def test_no_process_alive_throughout_the_call_is_missing(self) -> None:
        # proc_listpids does not report that it ran out of room, so a truncated
        # read is indistinguishable from a complete one - and a dropped second
        # match reads as an unambiguous target, the single condition that
        # permits a signal. Checked against ps rather than against this
        # function's own bookkeeping, which could only agree with itself.
        #
        # ps on both sides of the call, intersected: a process listed before and
        # after was alive throughout, so its absence from the listing is a real
        # gap rather than a process that started or exited alongside it.
        before = _ps_pids()
        listed = set(fw.list_pids())
        after = _ps_pids()
        alive_throughout = before & after
        self.assertGreater(len(alive_throughout), 50, "ps returned an implausible list")
        self.assertEqual(alive_throughout - listed, set())


class UnsafePathTest(unittest.TestCase):
    def setUp(self) -> None:
        # realpath, because unsafe_path_owners reports resolved components and
        # mkdtemp hands back a /var/folders path that is itself behind a symlink.
        self.directory = os.path.realpath(
            tempfile.mkdtemp(prefix="footprint-watchdog-paths.")
        )
        self.addCleanup(subprocess.run, ["rm", "-rf", self.directory], check=False)

    def test_a_system_directory_is_safe(self) -> None:
        self.assertEqual(fw.unsafe_path_owners("/usr/bin"), [])

    def test_a_world_writable_directory_is_unsafe(self) -> None:
        self.assertIn("/private/tmp", fw.unsafe_path_owners("/tmp"))

    def test_a_non_root_owned_directory_is_unsafe_even_at_0755(self) -> None:
        # The case a mode-only check misses: 0755 looks locked down, but the
        # owning account can still replace anything in it, and that account is
        # not root.
        target = os.path.join(self.directory, "sbin")
        os.makedirs(target, mode=0o755)
        self.assertIn(target, fw.unsafe_path_owners(target))

    def test_a_writable_ancestor_makes_a_locked_leaf_unsafe(self) -> None:
        # A leaf nobody can write is no protection if its parent can be swapped
        # out from under it.
        parent = os.path.join(self.directory, "parent")
        leaf = os.path.join(parent, "leaf")
        os.makedirs(leaf)
        os.chmod(parent, 0o777)
        self.assertIn(parent, fw.unsafe_path_owners(leaf))

    def test_a_symlink_into_a_safe_tree_is_still_unsafe(self) -> None:
        # The shape that resolving-before-auditing clears: the resolved path is
        # beyond reproach, while the link root actually traverses sits in a
        # directory anyone can write, so it can be repointed at will.
        link = os.path.join(self.directory, "link-to-root-dir")
        os.symlink("/var/db", link)
        self.assertIn(link, fw.unsafe_path_owners(link))

    def test_a_path_that_does_not_exist_is_judged_by_its_parent(self) -> None:
        # Nothing has been created yet at install time; what matters is who can
        # create it.
        missing = os.path.join(self.directory, "not-created-yet")
        self.assertEqual(
            fw.unsafe_path_owners(missing), fw.unsafe_path_owners(self.directory)
        )


class ReadSampleTest(unittest.TestCase):
    def test_footprint_reflects_a_real_allocation(self) -> None:
        target = TargetProcess(mib=64)
        self.addCleanup(target.close)
        pid, path = fw.find_targets(_target_bin)[0]
        sample = fw.read_sample(pid, path)
        assert sample is not None
        self.assertGreaterEqual(sample.footprint, 64 * 1024 ** 2)
        self.assertLess(sample.footprint, 128 * 1024 ** 2)
        self.assertGreater(sample.age_seconds, 0.0)
        # A wrong mach timebase reads ~40x high on Apple silicon, so a target
        # started seconds ago would claim minutes of age.
        self.assertLess(sample.age_seconds, 120.0)

    def test_unreadable_pid_reads_as_none(self) -> None:
        self.assertIsNone(fw.read_sample(999999, "/nonexistent"))


class WaitForReplacementTest(unittest.TestCase):
    """What counts as a replacement, and what only looks like one."""

    def wait(self, old_pid: int, timeout: float) -> Tuple[Optional[Tuple[int, str]], str]:
        return fw.wait_for_replacement(
            _target_bin, old_pid, timeout, time.time, time.sleep
        )

    def test_one_new_process_with_the_old_one_gone_is_a_replacement(self) -> None:
        target = TargetProcess(mib=1)
        self.addCleanup(target.close)
        replacement, reason = self.wait(old_pid=_DEAD_PID, timeout=INFINITE)
        self.assertEqual(reason, "replaced")
        assert replacement is not None
        self.assertEqual(replacement[0], target.process.pid)

    def test_a_still_running_original_is_not_a_replacement(self) -> None:
        # A target that ignores TERM can still be running when its supervisor
        # starts a second instance. Accepting the fresh one would report
        # recovery while the runaway is alive and still over the ceiling.
        original = TargetProcess(mib=1)
        self.addCleanup(original.close)
        newer = TargetProcess(mib=1)
        self.addCleanup(newer.close)
        replacement, reason = self.wait(
            old_pid=original.process.pid, timeout=EXPIRING_RESPAWN_SECONDS
        )
        self.assertIsNone(replacement)
        self.assertIn("still running", reason)

    def test_several_candidates_are_not_a_replacement(self) -> None:
        # With more than one match there is no way to say which the ceiling now
        # describes - the same reason a tick refuses an ambiguous target before
        # it signals anything.
        first = TargetProcess(mib=1)
        self.addCleanup(first.close)
        second = TargetProcess(mib=1)
        self.addCleanup(second.close)
        replacement, reason = self.wait(
            old_pid=_DEAD_PID, timeout=EXPIRING_RESPAWN_SECONDS
        )
        self.assertIsNone(replacement)
        self.assertIn("several", reason)

    def test_nothing_matching_is_reported_as_such(self) -> None:
        replacement, reason = self.wait(
            old_pid=_DEAD_PID, timeout=EXPIRING_RESPAWN_SECONDS
        )
        self.assertIsNone(replacement)
        self.assertIn("nothing matches", reason)


class RunTickTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.mkdtemp(prefix="footprint-watchdog-tick.")
        self.state_path = os.path.join(self.directory, "target.state.json")
        self.out = io.StringIO()

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", self.directory], check=False)

    def tick(
        self,
        ceiling: int,
        dry_run: bool = False,
        cooldown_seconds: float = 3600.0,
        state_path: Optional[str] = None,
        respawn_timeout: float = INFINITE,
    ) -> int:
        return fw.run_tick(
            spec=_target_bin,
            ceiling=ceiling,
            cooldown_seconds=cooldown_seconds,
            respawn_timeout=respawn_timeout,
            signal_name="TERM",
            state_path=self.state_path if state_path is None else state_path,
            context_command=None,
            dry_run=dry_run,
            now_fn=time.time,
            sleep_fn=time.sleep,
            out=self.out,
        )

    def records(self) -> List[Dict[str, object]]:
        return [
            cast(Dict[str, object], json.loads(line))
            for line in self.out.getvalue().splitlines()
            if line
        ]

    def only_record(self) -> Dict[str, object]:
        records = self.records()
        self.assertEqual(len(records), 1, self.out.getvalue())
        return records[0]

    def test_absent_target_is_reported_not_ignored(self) -> None:
        # A watchdog whose target vanished is not watching anything; staying
        # silent would be indistinguishable from a healthy tick.
        self.assertEqual(self.tick(ceiling=1024 ** 3), fw.EXIT_TARGET_ABSENT)
        self.assertEqual(self.only_record()["event"], "target_absent")

    def test_below_ceiling_writes_nothing_at_all(self) -> None:
        target = TargetProcess(mib=8)
        self.addCleanup(target.close)
        self.assertEqual(self.tick(ceiling=512 * 1024 ** 2), fw.EXIT_OK)
        self.assertEqual(self.out.getvalue(), "")

    def test_ambiguous_target_refuses_and_signals_nothing(self) -> None:
        first = TargetProcess(mib=8)
        self.addCleanup(first.close)
        second = TargetProcess(mib=8)
        self.addCleanup(second.close)
        before = sorted(first.pids())
        self.assertEqual(self.tick(ceiling=1), fw.EXIT_TARGET_AMBIGUOUS)
        self.assertEqual(self.only_record()["event"], "target_ambiguous")
        self.assertEqual(sorted(first.pids()), before)

    def test_dry_run_reports_the_crossing_without_signalling(self) -> None:
        target = TargetProcess(mib=64)
        self.addCleanup(target.close)
        before = target.pids()
        self.assertEqual(self.tick(ceiling=32 * 1024 ** 2, dry_run=True), fw.EXIT_OK)
        record = self.only_record()
        self.assertEqual(record["event"], "ceiling_crossed")
        self.assertIs(record["dry_run"], True)
        self.assertEqual(target.pids(), before)
        self.assertFalse(os.path.exists(self.state_path))

    def test_restart_recovers_and_reports_before_and_after(self) -> None:
        target = TargetProcess(mib=64, respawn_mib=0)
        self.addCleanup(target.close)
        original = target.pids()
        self.assertEqual(len(original), 1)
        self.assertEqual(self.tick(ceiling=32 * 1024 ** 2), fw.EXIT_OK)

        events = [record["event"] for record in self.records()]
        self.assertEqual(events, ["ceiling_crossed", "recovered"])
        recovered = self.records()[1]
        before = cast(Dict[str, object], recovered["before"])
        after = cast(Dict[str, object], recovered["after"])
        self.assertEqual(before["pid"], original[0])
        self.assertNotEqual(after["pid"], original[0])
        self.assertLess(int(str(after["footprint_bytes"])), 32 * 1024 ** 2)

    def test_the_cooldown_stamp_lands_before_the_signal(self) -> None:
        # The stamp has to be durable before the irreversible half happens. If
        # it were written after the kill, anything ending this process in
        # between - a crash, a SIGKILL, a failed write - would leave the next
        # tick free to signal again, which is the loop the cooldown prevents.
        # Proven by making the write fail: no stamp means no signal.
        target = TargetProcess(mib=64)
        self.addCleanup(target.close)
        before = target.pids()
        unwritable = os.path.join(self.directory, "no-such-dir", "target.state.json")
        self.assertEqual(
            self.tick(ceiling=32 * 1024 ** 2, state_path=unwritable),
            fw.EXIT_UNSAFE_PATH,
        )
        events = [record["event"] for record in self.records()]
        self.assertEqual(events, ["ceiling_crossed", "cooldown_stamp_failed"])
        self.assertEqual(target.pids(), before)

    def test_failed_respawn_still_records_the_cooldown_stamp(self) -> None:
        # Without a supervisor nothing replaces the target. The stamp must land
        # anyway: a failure that leaves the cooldown unset lets the next tick
        # signal again, which is the restart loop this is built to avoid.
        target = TargetProcess(mib=64)
        self.addCleanup(target.close)
        self.assertEqual(
            self.tick(ceiling=32 * 1024 ** 2, respawn_timeout=EXPIRING_RESPAWN_SECONDS),
            fw.EXIT_RESPAWN_FAILED,
        )
        events = [record["event"] for record in self.records()]
        self.assertEqual(events, ["ceiling_crossed", "recovery_unconfirmed"])
        self.assertIn("last_restart_epoch", fw.read_state(self.state_path))

    def test_replacement_still_above_ceiling_is_reported_not_retried(self) -> None:
        # A ceiling below any fresh process means every replacement is "still too
        # big" deterministically, with no dependence on how fast the supervisor
        # re-allocates.
        target = TargetProcess(mib=8, respawn_mib=8)
        self.addCleanup(target.close)
        self.assertEqual(self.tick(ceiling=1), fw.EXIT_REPLACEMENT_ABOVE_CEILING)
        events = [record["event"] for record in self.records()]
        self.assertEqual(events, ["ceiling_crossed", "replacement_above_ceiling"])

    def test_cooldown_suppresses_a_second_restart(self) -> None:
        target = TargetProcess(mib=64, respawn_mib=64)
        self.addCleanup(target.close)
        self.assertEqual(self.tick(ceiling=32 * 1024 ** 2), fw.EXIT_REPLACEMENT_ABOVE_CEILING)
        surviving = target.pids()

        self.out = io.StringIO()
        self.assertEqual(self.tick(ceiling=32 * 1024 ** 2), fw.EXIT_COOLDOWN_SUPPRESSED)
        self.assertEqual(self.only_record()["event"], "cooldown_suppressed")
        self.assertEqual(target.pids(), surviving)


if __name__ == "__main__":
    unittest.main()
