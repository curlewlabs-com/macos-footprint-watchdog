"""Tests for footprint_watchdog.

The integration cases drive real processes through the real kernel ledger rather
than a mocked measurement, because every bug worth catching here lives in the
boundary: what `proc_pidpath` actually reports, whether a signalled process is
actually replaced, whether the ledger actually reflects an allocation. A mocked
`read_sample` would assert that the arithmetic in this file is self-consistent,
which was never in doubt.

The target is compiled per run -- see test/footprint_target.c for why nothing
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
from typing import Dict, List, Optional, cast

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import footprint_watchdog as fw  # noqa: E402

# Long enough that a target outlives the case driving it, short enough that a
# leaked process disappears on its own rather than lingering on a dev machine.
TARGET_LIFETIME_SECONDS = 90
# The respawn wait a supervisor-backed case allows. A shell loop re-execs in
# milliseconds; this is a backstop against a hang, not a tuned delay, so it is
# far above the expected value and still short enough to fail a run fast.
TEST_RESPAWN_TIMEOUT_SECONDS = 15.0
# How long to wait for a target to report that its allocation is resident.
READY_TIMEOUT_SECONDS = 30.0

_build_dir = ""
_target_bin = ""


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


def _wait_for_ready(process: "subprocess.Popen[str]") -> None:
    """Block until the target reports its allocation is dirtied and resident."""
    assert process.stderr is not None
    deadline = time.time() + READY_TIMEOUT_SECONDS
    while time.time() < deadline:
        line = process.stderr.readline()
        if "ready" in line:
            return
        if process.poll() is not None:
            raise AssertionError("target exited before signalling ready")
    raise AssertionError("target did not signal ready within %.0fs" % READY_TIMEOUT_SECONDS)


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
        self.process.wait(timeout=10)


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
    ) -> int:
        return fw.run_tick(
            spec=_target_bin,
            ceiling=ceiling,
            cooldown_seconds=cooldown_seconds,
            respawn_timeout=TEST_RESPAWN_TIMEOUT_SECONDS,
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

    def test_failed_respawn_still_records_the_cooldown_stamp(self) -> None:
        # Without a supervisor nothing replaces the target. The stamp must land
        # anyway: a failure that leaves the cooldown unset lets the next tick
        # signal again, which is the restart loop this is built to avoid.
        target = TargetProcess(mib=64)
        self.addCleanup(target.close)
        self.assertEqual(self.tick(ceiling=32 * 1024 ** 2), fw.EXIT_RESPAWN_FAILED)
        events = [record["event"] for record in self.records()]
        self.assertEqual(events, ["ceiling_crossed", "respawn_failed"])
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
