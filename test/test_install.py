"""Tests for install.py.

There is no test that the generated plist equals a literal dict: that would fail
on every legitimate edit while catching nothing. What is checked here is the pair
of invariants that cross a component boundary, where a mismatch produces a daemon
that fails silently every interval:

- the arguments the installer writes into the plist are arguments the watchdog's
  own parser accepts, and
- `--verify` actually notices when what is installed stops matching the source.
"""

from __future__ import annotations

import argparse
import contextlib
import filecmp
import io
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import List, Optional, cast

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import footprint_watchdog as fw  # noqa: E402
import install  # noqa: E402


class LabelTest(unittest.TestCase):
    def test_label_survives_an_absolute_path_target(self) -> None:
        # launchctl rejects a label containing a path separator, and the natural
        # way to name a target is the absolute path the tool prefers.
        label = install.label_for("/System/Library/Frameworks/Foo.framework/fseventsd")
        self.assertNotIn("/", label)
        self.assertTrue(label.startswith(install.LABEL_PREFIX))

    def test_distinct_targets_get_distinct_labels(self) -> None:
        # Two watched processes on one host must not collide onto one job.
        self.assertNotEqual(install.label_for("fseventsd"), install.label_for("mds_stores"))


class GeneratedArgumentsTest(unittest.TestCase):
    """The installer's output has to be input the watchdog accepts."""

    def parse_generated(self, **kwargs: object) -> List[str]:
        contents = install.build_plist(
            process=str(kwargs.get("process", "fseventsd")),
            ceiling=str(kwargs.get("ceiling", "2GiB")),
            interval=300,
            executable="/usr/local/sbin/footprint-watchdog",
            log_path="/var/log/footprint-watchdog.log",
            cooldown=kwargs.get("cooldown"),  # type: ignore[arg-type]
            context_command=kwargs.get("context_command"),  # type: ignore[arg-type]
            signal_name=kwargs.get("signal_name"),  # type: ignore[arg-type]
        )
        return cast(List[str], contents["ProgramArguments"])

    def test_minimal_arguments_parse_in_the_watchdog(self) -> None:
        arguments = self.parse_generated()
        parsed = fw.build_parser().parse_args(arguments[1:])
        self.assertEqual(parsed.process, "fseventsd")
        self.assertEqual(fw.parse_size(str(parsed.ceiling)), 2 * 1024 ** 3)

    def test_every_optional_argument_parses_too(self) -> None:
        arguments = self.parse_generated(
            cooldown=1800, context_command="Runner.Worker", signal_name="KILL"
        )
        parsed = fw.build_parser().parse_args(arguments[1:])
        self.assertEqual(parsed.cooldown, 1800)
        self.assertEqual(parsed.context_command, "Runner.Worker")
        self.assertEqual(parsed.signal, "KILL")

    def test_the_first_argument_is_the_executable_launchd_will_run(self) -> None:
        self.assertEqual(self.parse_generated()[0], "/usr/local/sbin/footprint-watchdog")


class LogDestinationTest(unittest.TestCase):
    """launchd opens this path as root on every run."""

    def setUp(self) -> None:
        self.directory = os.path.realpath(
            tempfile.mkdtemp(prefix="footprint-watchdog-log.")
        )
        self.addCleanup(subprocess.run, ["rm", "-rf", self.directory], check=False)

    def assert_refused(self, log_path: str) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                install.require_root_only_log(log_path)

    def test_a_directory_a_non_root_account_owns_is_refused(self) -> None:
        # The spelling this exists for: any account that can write the directory
        # can pre-place a symlink and choose a file for root to append to.
        self.assert_refused(os.path.join(self.directory, "watchdog.log"))

    def test_a_missing_directory_is_refused(self) -> None:
        # launchd cannot create intermediate directories, so it would discard
        # every record while the install reported success.
        self.assert_refused("/var/log/no-such-dir-here/watchdog.log")

    def test_a_non_regular_existing_log_is_refused(self) -> None:
        # Root blocks writing to an unread fifo, taking the watchdog with it.
        fifo = os.path.join(self.directory, "watchdog.log")
        os.mkfifo(fifo)
        self.assert_refused(fifo)

    def test_a_symlink_is_refused(self) -> None:
        link = os.path.join(self.directory, "watchdog.log")
        os.symlink("/etc/hosts", link)
        self.assert_refused(link)


class CeilingValidationTest(unittest.TestCase):
    def test_an_unparseable_ceiling_fails_at_parse_time(self) -> None:
        # At parse time specifically: rejected there, nothing downstream runs,
        # so no filesystem write can precede the error. Left to the watchdog's
        # first tick instead, the install reports success and leaves a job that
        # can only fail, once an interval, forever.
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                install.build_parser().parse_args(
                    ["--process", "fseventsd", "--ceiling", "potatoes"]
                )

    def test_the_validator_rejects_what_the_watchdog_would_reject(self) -> None:
        for bad in ("potatoes", "", "-1", "0", "1e9"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                install.ceiling_string(bad)

    def test_a_valid_ceiling_still_parses(self) -> None:
        parsed = install.build_parser().parse_args(
            ["--process", "fseventsd", "--ceiling", "2GiB"]
        )
        self.assertEqual(parsed.ceiling, "2GiB")

    def test_the_operator_spelling_is_kept_verbatim(self) -> None:
        # The plist carries what was written, so validation must not normalise
        # it into some other spelling behind the operator's back.
        self.assertEqual(install.ceiling_string("2GiB"), "2GiB")
        self.assertEqual(install.ceiling_string("512MB"), "512MB")


class InstallExecutableTest(unittest.TestCase):
    """launchd may exec the destination at any moment, including mid-install."""

    def setUp(self) -> None:
        self.directory = os.path.realpath(
            tempfile.mkdtemp(prefix="footprint-watchdog-exe.")
        )
        self.addCleanup(subprocess.run, ["rm", "-rf", self.directory], check=False)
        self.destination = os.path.join(self.directory, install.INSTALLED_NAME)
        self.source = os.path.join(install.REPO_ROOT, install.SOURCE_NAME)

    def test_the_installed_file_matches_the_source_and_is_executable(self) -> None:
        install.install_executable(self.source, self.destination)
        self.assertTrue(filecmp.cmp(self.source, self.destination, shallow=False))
        self.assertTrue(os.stat(self.destination).st_mode & 0o111)

    def test_a_failed_copy_leaves_the_previous_install_intact(self) -> None:
        # The reason this is a rename rather than a copy onto the destination:
        # copying truncates first, so a failure part-way leaves root executing a
        # partial file every interval.
        with open(self.destination, "w", encoding="utf-8") as stream:
            stream.write("#!/usr/bin/python3\n# the previous install\n")
        with self.assertRaises(OSError):
            install.install_executable(
                os.path.join(self.directory, "no-such-source"), self.destination
            )
        with open(self.destination, encoding="utf-8") as stream:
            self.assertIn("the previous install", stream.read())
        self.assertEqual(os.listdir(self.directory), [install.INSTALLED_NAME])


class PlistsReferencingTest(unittest.TestCase):
    """One executable serves every watched target."""

    def setUp(self) -> None:
        self.daemons = os.path.realpath(
            tempfile.mkdtemp(prefix="footprint-watchdog-daemons.")
        )
        self.addCleanup(subprocess.run, ["rm", "-rf", self.daemons], check=False)
        self.original_daemons = install.LAUNCH_DAEMONS
        install.LAUNCH_DAEMONS = self.daemons
        self.addCleanup(setattr, install, "LAUNCH_DAEMONS", self.original_daemons)
        self.executable = "/usr/local/sbin/footprint-watchdog"

    def write_job(self, process: str, executable: Optional[str] = None) -> str:
        path = install.plist_path_for(process)
        install.write_plist(
            path,
            install.build_plist(
                process=process,
                ceiling="2GiB",
                interval=300,
                executable=executable or self.executable,
                log_path="/var/log/footprint-watchdog.log",
                cooldown=None,
                context_command=None,
            ),
        )
        return path

    def test_every_job_pointing_at_the_executable_is_reported(self) -> None:
        first = self.write_job("fseventsd")
        second = self.write_job("mds_stores")
        self.assertEqual(
            sorted(install.plists_referencing(self.executable)), sorted([first, second])
        )

    def test_removing_one_job_leaves_the_other_holding_the_executable(self) -> None:
        # Uninstalling one target must not delete the binary its sibling runs.
        first = self.write_job("fseventsd")
        second = self.write_job("mds_stores")
        os.unlink(first)
        self.assertEqual(install.plists_referencing(self.executable), [second])

    def test_the_last_job_going_away_orphans_the_executable(self) -> None:
        os.unlink(self.write_job("fseventsd"))
        self.assertEqual(install.plists_referencing(self.executable), [])

    def test_a_job_running_a_different_executable_is_not_counted(self) -> None:
        self.write_job("fseventsd", executable="/opt/elsewhere/footprint-watchdog")
        self.assertEqual(install.plists_referencing(self.executable), [])

    def test_an_unreadable_job_counts_as_a_reference(self) -> None:
        # It might reference the executable, and guessing that it does not is
        # the guess that deletes a binary something still runs.
        path = install.plist_path_for("fseventsd")
        with open(path, "wb") as stream:
            stream.write(b"not a plist")
        self.assertEqual(install.plists_referencing(self.executable), [path])


class VerifyTest(unittest.TestCase):
    """`--verify` has to fail on drift, or it is worse than not existing."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="footprint-watchdog-verify.")
        self.prefix = os.path.join(self.root, "sbin")
        self.daemons = os.path.join(self.root, "LaunchDaemons")
        os.makedirs(self.prefix)
        os.makedirs(self.daemons)
        self.original_daemons = install.LAUNCH_DAEMONS
        install.LAUNCH_DAEMONS = self.daemons

        installed = os.path.join(self.prefix, install.INSTALLED_NAME)
        shutil.copyfile(os.path.join(install.REPO_ROOT, install.SOURCE_NAME), installed)
        # copyfile does not carry the mode over, and do_install sets 0755. Match
        # a real install here, or the exec-bit case below would assert against a
        # file that was never executable and could not fail.
        os.chmod(installed, 0o755)
        self.args = argparse.Namespace(
            process="fseventsd",
            ceiling="2GiB",
            interval=300,
            cooldown=None,
            context_command=None,
            log="/var/log/footprint-watchdog.log",
            prefix=self.prefix,
            signal=None,
        )
        install.write_plist(
            install.plist_path_for("fseventsd"),
            install.build_plist(
                process="fseventsd",
                ceiling="2GiB",
                interval=300,
                executable=os.path.join(self.prefix, install.INSTALLED_NAME),
                log_path="/var/log/footprint-watchdog.log",
                cooldown=None,
                context_command=None,
            ),
        )

    def tearDown(self) -> None:
        install.LAUNCH_DAEMONS = self.original_daemons
        subprocess.run(["rm", "-rf", self.root], check=False)

    def codes(self) -> List[str]:
        return [code for code, _ in install.verify_problems(self.args)]

    def test_matching_content_reports_no_content_or_plist_drift(self) -> None:
        # A test cannot create root-owned files in a root-owned directory, so
        # the ownership findings fire here by construction. What this asserts is
        # that neither comparison found a difference; the mutation cases below
        # prove those same comparisons do fire when there is one.
        codes = self.codes()
        self.assertNotIn("executable_content_differs", codes)
        self.assertNotIn("launchdaemon_differs", codes)
        self.assertNotIn("executable_not_executable", codes)

    def test_an_install_directory_a_non_root_account_owns_is_drift(self) -> None:
        # The prefix here is a temp directory owned by the test user - the exact
        # shape that lets an account other than root replace what root runs.
        self.assertIn("executable_dir_unsafe", self.codes())

    def test_an_edited_plist_is_drift(self) -> None:
        # The case this exists for: someone changed the ceiling on one host by
        # editing the plist, so the machine and the repo silently disagree.
        path = install.plist_path_for("fseventsd")
        with open(path, "rb") as stream:
            contents = plistlib.load(stream)
        contents["ProgramArguments"] = ["/usr/local/sbin/footprint-watchdog", "--process", "fseventsd"]
        install.write_plist(path, contents)
        self.assertIn("launchdaemon_differs", self.codes())

    def test_an_edited_executable_is_drift(self) -> None:
        with open(os.path.join(self.prefix, install.INSTALLED_NAME), "a", encoding="utf-8") as stream:
            stream.write("\n# local edit\n")
        self.assertIn("executable_content_differs", self.codes())

    def test_an_unreadable_executable_is_drift_not_a_traceback(self) -> None:
        # Config management runs --verify; a raise here is a traceback nobody
        # can act on where a drift record was promised.
        os.chmod(os.path.join(self.prefix, install.INSTALLED_NAME), 0o000)
        self.assertIn("executable_unreadable", self.codes())

    def test_a_corrupt_plist_is_drift_not_a_traceback(self) -> None:
        with open(install.plist_path_for("fseventsd"), "wb") as stream:
            stream.write(b"not a plist")
        self.assertIn("launchdaemon_unreadable", self.codes())

    def test_a_malformed_xml_plist_is_drift_not_a_traceback(self) -> None:
        # Malformed XML surfaces the parser's own ExpatError, which is not a
        # ValueError - so catching ValueError alone would let this one escape.
        with open(install.plist_path_for("fseventsd"), "wb") as stream:
            stream.write(b'<?xml version="1.0"?><plist><dict><key>a</key>')
        self.assertIn("launchdaemon_unreadable", self.codes())

    def test_a_missing_install_is_drift(self) -> None:
        os.unlink(os.path.join(self.prefix, install.INSTALLED_NAME))
        self.assertIn("executable_missing", self.codes())

    def test_an_installed_file_launchd_cannot_execute_is_drift(self) -> None:
        # Content, owner, and write bits can all be right on a 0644 file, and a
        # watchdog that never runs reports nothing at all.
        os.chmod(os.path.join(self.prefix, install.INSTALLED_NAME), 0o644)
        self.assertIn("executable_not_executable", self.codes())

    def test_a_world_writable_executable_is_drift(self) -> None:
        # The privilege-escalation shape: root runs this file every interval.
        os.chmod(os.path.join(self.prefix, install.INSTALLED_NAME), 0o777)
        self.assertIn("executable_writable_by_non_root", self.codes())

    def test_do_verify_maps_any_problem_to_a_non_zero_exit(self) -> None:
        os.unlink(install.plist_path_for("fseventsd"))
        with contextlib.redirect_stderr(io.StringIO()) as captured:
            self.assertEqual(install.do_verify(self.args), 1)
        self.assertIn("launchdaemon_missing", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
