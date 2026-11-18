"""Tests for the FSEvents history ceiling.

The purge cases run against the real fseventsd, on an APFS disk image this
suite creates and attaches, never on the host's own volumes: a mocked purge
would only assert that this file agrees with itself, and the behaviours worth
catching - what the time lookup answers, which journal files a purge removes,
whether the store's UUID changes, whether the purge stays on its own device -
belong to fseventsd. Those cases need root, which is what attaching an image
fseventsd records and calling the purge both require, so CI runs this module a
second time under sudo; without root they skip.
"""

from __future__ import annotations

import io
import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from typing import cast

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import footprint_watchdog as fw

# Practical INFINITE for this runner: neither wait here, for fseventsd to take
# up a volume after a mount and for a busy disk to eject, is meant to reach it.
# Higher than test_footprint_watchdog's because what they wait on is the
# system, and on CI these cases can run a minute after the runner boots, with
# the load average above a hundred.
INFINITE = 300.0
_JOURNAL_NAME = re.compile(r"[0-9a-f]{16}")
_DATA_VOLUME = "/System/Volumes/Data"


class ResolveHistoryCeilingTest(unittest.TestCase):
    def test_fseventsd_gets_the_default_without_asking(self) -> None:
        self.assertEqual(
            fw.resolve_history_ceiling("fseventsd", None),
            fw.parse_size(fw.DEFAULT_HISTORY_CEILING),
        )

    def test_fseventsd_named_by_absolute_path_gets_it_too(self) -> None:
        # The tool prefers an absolute --process; the default must not depend
        # on which spelling an operator chose.
        path = (
            "/System/Library/Frameworks/CoreServices.framework/Versions/A/"
            "Frameworks/FSEvents.framework/Versions/A/Support/fseventsd"
        )
        self.assertEqual(
            fw.resolve_history_ceiling(path, None),
            fw.parse_size(fw.DEFAULT_HISTORY_CEILING),
        )

    def test_any_other_target_purges_nothing_by_default(self) -> None:
        # Watching mds_stores must not start purging the host's event history.
        self.assertIsNone(fw.resolve_history_ceiling("mds_stores", None))

    def test_off_turns_it_off_for_fseventsd(self) -> None:
        self.assertIsNone(fw.resolve_history_ceiling("fseventsd", "off"))
        self.assertIsNone(fw.resolve_history_ceiling("fseventsd", "OFF"))

    def test_an_explicit_size_wins_for_any_target(self) -> None:
        self.assertEqual(fw.resolve_history_ceiling("mds_stores", "2GiB"), 2 * 1024**3)

    def test_an_unparseable_ceiling_is_an_error_not_off(self) -> None:
        with self.assertRaises(ValueError):
            fw.resolve_history_ceiling("fseventsd", "of")


class MountPointTest(unittest.TestCase):
    def test_the_data_volume_is_its_own_mount_point(self) -> None:
        # The case os.path.ismount gets wrong: firmlinks give /System/Volumes
        # the Data volume's device, so the default volume would be refused.
        self.assertEqual(fw.mount_point(_DATA_VOLUME), _DATA_VOLUME)

    def test_a_directory_inside_a_volume_is_not(self) -> None:
        directory = os.path.realpath(tempfile.mkdtemp(prefix="footprint-watchdog-mnt."))
        self.addCleanup(os.rmdir, directory)
        self.assertNotEqual(fw.mount_point(directory), directory)

    def test_a_path_that_is_not_a_mount_point_is_refused_before_any_purge(self) -> None:
        # The purge acts on whichever device a path is on, so a mistyped
        # --history-volume would otherwise purge the volume that contains it.
        directory = os.path.realpath(tempfile.mkdtemp(prefix="footprint-watchdog-mnt."))
        self.addCleanup(os.rmdir, directory)
        out = io.StringIO()
        code = fw.run_history_tick(
            volume=directory,
            ceiling=1,
            cooldown_seconds=3600.0,
            state_path=None,
            dry_run=False,
            now_fn=time.time,
            out=out,
        )
        self.assertEqual(code, fw.EXIT_USAGE)
        self.assertEqual(
            json.loads(out.getvalue())["event"], "history_volume_not_mounted"
        )


@unittest.skipUnless(
    os.geteuid() == 0, "attaching a recorded volume and purging need root"
)
class HistoryTickTest(unittest.TestCase):
    volume = ""
    device = ""
    image = ""
    image_dir = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.image_dir = tempfile.mkdtemp(prefix="footprint-watchdog-image.")
        name = f"fswatchdog-{uuid.uuid4().hex[:8]}"
        cls.image = os.path.join(cls.image_dir, name + ".dmg")
        subprocess.run(
            [
                "/usr/bin/hdiutil",
                "create",
                "-quiet",
                "-size",
                "64m",
                "-fs",
                "APFS",
                "-volname",
                name,
                cls.image,
            ],
            check=True,
        )
        cls.attach()

    @classmethod
    def attach(cls) -> None:
        # A plain attach, not -nobrowse: fseventsd keeps no history for a
        # volume attached hidden, and a test volume without one tests nothing.
        # The mount point is read back rather than assumed, since a reattach
        # can land on another path if the last one is still being torn down.
        listing = subprocess.run(
            ["/usr/bin/hdiutil", "attach", "-plist", cls.image],
            check=True,
            capture_output=True,
        ).stdout
        entities = cast(
            list[dict[str, object]], plistlib.loads(listing)["system-entities"]
        )
        (cls.volume,) = [
            str(entity["mount-point"]) for entity in entities if "mount-point" in entity
        ]
        # The image's own disk, not the APFS container synthesized on it:
        # detaching that one takes the container and the volume with it.
        (cls.device,) = [
            str(entity["dev-entry"])
            for entity in entities
            if entity.get("content-hint") == "GUID_partition_scheme"
        ]
        cls.wait_for_fseventsd()

    @classmethod
    def wait_for_fseventsd(cls) -> None:
        """Block until fseventsd has taken up the volume just attached.

        It does that asynchronously after the mount, and on a runner a minute
        after boot it took long enough that a case asking for the store's UUID
        right after a reattach got none. fseventsd answers a volume's UUID once
        it has the volume's history open, so that answer is the readiness this
        waits for. A fresh volume has no history until its first recorded
        change, so each poll makes one: the wait never depends on a change
        fseventsd might have seen before it was ready.
        """
        device = os.stat(cls.volume).st_dev
        started = time.monotonic()
        while fw.history_uuid(device) is None:
            if time.monotonic() - started > INFINITE:
                raise AssertionError(
                    f"fseventsd did not take up {cls.volume} within {INFINITE:.0f}s"
                )
            with open(os.path.join(cls.volume, "attached"), "w") as stream:
                stream.write("x")
            time.sleep(0.1)
        waited = time.monotonic() - started
        if waited > 1.0:
            print(
                f"fseventsd took {waited:.1f}s to take up {cls.volume}",
                file=sys.stderr,
            )

    @classmethod
    def tearDownClass(cls) -> None:
        # Empty when a reattach failed: the number of a disk this class already
        # detached can belong to someone else's image by now.
        if cls.device:
            subprocess.run(
                ["/usr/bin/hdiutil", "detach", "-quiet", "-force", cls.device],
                check=False,
            )
        subprocess.run(["rm", "-rf", cls.image_dir], check=False)

    def setUp(self) -> None:
        self.state_dir = tempfile.mkdtemp(prefix="footprint-watchdog-state.")
        self.addCleanup(subprocess.run, ["rm", "-rf", self.state_dir], check=False)
        self.state_path = os.path.join(self.state_dir, "fseventsd.state.json")
        self.out = io.StringIO()
        no_log = os.path.join(self.volume, ".fseventsd", "no_log")
        if os.path.exists(no_log):
            os.unlink(no_log)
            # On macOS 26 a volume whose marker was removed while it was
            # mounted recorded nothing more until it was mounted again.
            self.remount()

    def journal_files(self) -> list[str]:
        directory = os.path.join(self.volume, ".fseventsd")
        # fseventsd creates the directory with the volume's first recorded
        # change, not at attach.
        if not os.path.isdir(directory):
            return []
        return sorted(
            name for name in os.listdir(directory) if _JOURNAL_NAME.fullmatch(name)
        )

    def remount(self) -> None:
        self.detach()
        type(self).attach()

    def detach(self) -> None:
        """Detach the image, unforced, retrying while macOS calls it busy.

        Shortly after boot hdiutil has unmounted the volume and then failed to
        eject the disk with "Resource busy", with nothing open on the volume.
        The disk frees itself; nothing here can hurry it. Retrying names the
        whole disk, so a retry after the unmount went through ejects what is
        left rather than looking for a mount point that is already gone.
        """
        started = time.monotonic()
        refusals: list[str] = []
        while True:
            detach = subprocess.run(
                ["/usr/bin/hdiutil", "detach", self.device],
                capture_output=True,
                text=True,
                check=False,
            )
            if detach.returncode == 0:
                type(self).device = ""
                break
            # Name whatever held the volume, so a refusal says who refused.
            holders = subprocess.run(
                ["/usr/sbin/lsof", "+f", "--", self.volume],
                capture_output=True,
                text=True,
                check=False,
            )
            refusal = (
                f"detach of {self.device} exited {detach.returncode}: "
                f"{detach.stderr.strip()}; open on {self.volume}: "
                f"{holders.stdout.strip() or 'nothing'}"
            )
            print(refusal, file=sys.stderr)
            refusals.append(refusal)
            if time.monotonic() - started > INFINITE:
                self.fail("\n".join(refusals))
            time.sleep(1.0)

    def record_history(self, batches: int) -> None:
        """Make changes on the volume and have fseventsd write them to a new
        journal file, `batches` times over.

        By remounting, not by writing until a journal shows up. fseventsd holds
        a volume's recent events in memory and writes a journal file when that
        buffer fills, at a size it does not publish; how long a burst of writes
        takes to fill it depends on how fast the runner's disk and fseventsd
        are at the time, and on a busy CI runner a minute of writes has passed
        without one. Unmounting is the trigger fseventsd always
        answers: it writes out what it holds for the volume and closes its
        journal, and an unforced detach cannot complete while that file is
        still open on the volume. So each new journal is on disk by the time
        the detach returns, and the check after the reattach needs no wait.
        """
        for _ in range(batches):
            before = self.journal_files()
            batch = uuid.uuid4().hex[:8]
            for index in range(100):
                path = os.path.join(self.volume, f"change-{batch}-{index:d}")
                with open(path, "w") as stream:
                    stream.write("x")
            self.remount()
            after = self.journal_files()
            self.assertTrue(
                set(after) - set(before),
                f"no new journal file after a remount: before {before}, after {after}",
            )

    def tick(self, ceiling: int, dry_run: bool = False) -> int:
        return fw.run_history_tick(
            volume=self.volume,
            ceiling=ceiling,
            cooldown_seconds=3600.0,
            state_path=self.state_path,
            dry_run=dry_run,
            now_fn=time.time,
            out=self.out,
        )

    def records(self) -> list[dict[str, object]]:
        return [
            cast(dict[str, object], json.loads(line))
            for line in self.out.getvalue().splitlines()
            if line
        ]

    def measured(self) -> fw.HistorySample:
        sample = fw.read_history(self.volume)
        assert sample is not None
        return sample

    def test_below_the_ceiling_writes_nothing_and_purges_nothing(self) -> None:
        self.record_history(1)
        before = self.measured()
        self.assertEqual(self.tick(ceiling=before.history_bytes + 1024**3), fw.EXIT_OK)
        self.assertEqual(self.out.getvalue(), "")
        self.assertEqual(self.measured().uuid, before.uuid)

    def test_a_dry_run_reports_the_crossing_and_leaves_the_store_alone(self) -> None:
        self.record_history(2)
        before = self.measured()
        self.assertEqual(self.tick(ceiling=1, dry_run=True), fw.EXIT_OK)
        (record,) = self.records()
        self.assertEqual(record["event"], "history_ceiling_crossed")
        self.assertIs(record["dry_run"], True)
        self.assertEqual(self.measured().uuid, before.uuid)
        self.assertFalse(os.path.exists(self.state_path))

    def test_a_purge_shrinks_the_history_and_rotates_only_this_volumes_uuid(
        self,
    ) -> None:
        # The UUID is what tells a client its saved position is gone, so a purge
        # that changed it nowhere, or changed the host's, would be the bug.
        data_uuid = fw.history_uuid(os.stat(_DATA_VOLUME).st_dev)
        self.record_history(2)
        before = self.measured()
        self.assertEqual(
            self.tick(ceiling=before.history_bytes - 1), fw.EXIT_OK, self.out.getvalue()
        )
        (record,) = [r for r in self.records() if r["event"] == "history_purged"]
        after = cast(dict[str, object], record["after"])
        self.assertLess(cast(int, after["history_bytes"]), before.history_bytes)
        self.assertNotEqual(after["uuid"], before.uuid)
        self.assertEqual(fw.history_uuid(os.stat(_DATA_VOLUME).st_dev), data_uuid)

    def test_a_history_back_over_the_ceiling_inside_the_cooldown_is_not_purged_again(
        self,
    ) -> None:
        # Each purge forces every saved-position client to rescan; purging in a
        # loop would do that every tick.
        self.record_history(2)
        ceiling = self.measured().history_bytes - 1
        self.assertEqual(self.tick(ceiling=ceiling), fw.EXIT_OK, self.out.getvalue())
        rotated = self.measured().uuid
        while self.measured().history_bytes <= ceiling:
            self.record_history(1)
        self.assertEqual(self.tick(ceiling=ceiling), fw.EXIT_COOLDOWN_SUPPRESSED)
        self.assertEqual(self.records()[-1]["event"], "history_cooldown_suppressed")
        self.assertEqual(self.measured().uuid, rotated)

    def test_a_volume_whose_owner_turned_history_off_is_left_alone(self) -> None:
        # A CI guest with the no_log marker runs this same tick every interval;
        # its switched-off history is a configuration, not a failure.
        self.record_history(1)
        with open(os.path.join(self.volume, ".fseventsd", "no_log"), "w"):
            pass
        self.assertEqual(self.tick(ceiling=1), fw.EXIT_OK)
        self.assertEqual(self.out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
