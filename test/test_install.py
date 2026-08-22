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
import io
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import List, cast

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

        shutil.copyfile(
            os.path.join(install.REPO_ROOT, install.SOURCE_NAME),
            os.path.join(self.prefix, install.INSTALLED_NAME),
        )
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

    def test_matching_content_reports_no_content_drift(self) -> None:
        # A test cannot create a root-owned file, so the ownership check fires
        # here by construction. Asserting it is the ONLY finding is what proves
        # the content and plist comparisons both passed.
        self.assertEqual(self.codes(), ["executable_not_root_owned"])

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

    def test_a_missing_install_is_drift(self) -> None:
        os.unlink(os.path.join(self.prefix, install.INSTALLED_NAME))
        self.assertIn("executable_missing", self.codes())

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
