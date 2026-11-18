"""Temporary, removed before merge: the old churn wait, instrumented.

Writes 2000 files a round with a 1s pause, as the old helper did, for up to
120s on a fresh 64 MiB image, and prints each round's write time, the files
written so far and the journal files on disk. Then times an unforced and a
forced detach, each after a small batch of writes, and reports whether the
batch reached a journal.
"""

import os
import plistlib
import re
import subprocess
import tempfile
import time
import uuid

JOURNAL = re.compile(r"[0-9a-f]{16}")


def attach(image):
    out = subprocess.run(
        ["/usr/bin/hdiutil", "attach", "-plist", image], check=True, capture_output=True
    ).stdout
    entities = plistlib.loads(out)["system-entities"]
    return next(e["mount-point"] for e in entities if "mount-point" in e)


def journals(volume):
    directory = os.path.join(volume, ".fseventsd")
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return {}
    return {
        n: os.stat(os.path.join(directory, n)).st_size
        for n in names
        if JOURNAL.fullmatch(n)
    }


def detach_cycle(image, volume, label, force):
    before = journals(volume)
    for index in range(100):
        with open(os.path.join(volume, f"{label}-{index}"), "w") as stream:
            stream.write("x")
    start = time.time()
    command = ["/usr/bin/hdiutil", "detach", "-quiet"]
    result = subprocess.run(
        command + (["-force"] if force else []) + [volume], check=False
    )
    took = time.time() - start
    volume = attach(image)
    new = sorted(set(journals(volume)) - set(before))
    print(
        f"{label}: detach rc={result.returncode} took {took:.2f}s, new journals {new}"
    )
    return volume


def main():
    directory = tempfile.mkdtemp(prefix="churn-probe.")
    name = f"probe-{uuid.uuid4().hex[:8]}"
    image = os.path.join(directory, name + ".dmg")
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
            image,
        ],
        check=True,
    )
    volume = attach(image)
    start = time.time()
    files = 0
    round_number = 0
    seen = {}
    while time.time() - start < 120 and len(journals(volume)) < 2:
        round_number += 1
        round_start = time.time()
        try:
            for index in range(2000):
                path = os.path.join(volume, f"churn-{round_number}-{index}")
                with open(path, "w") as stream:
                    stream.write("x")
                files += 1
        except OSError as exc:
            print(f"round {round_number}: {exc} after {files} files")
            break
        wrote = time.time() - round_start
        time.sleep(1.0)
        now = journals(volume)
        print(
            f"round {round_number}: wrote 2000 in {wrote:.2f}s, t={time.time() - start:.1f}s,"
            f" files={files}, journals={len(now)} sizes={sorted(now.values())}"
        )
        seen = now
    print(
        f"churn ended at t={time.time() - start:.1f}s with {len(seen)} journals, {files} files"
    )
    volume = detach_cycle(image, volume, "unforced-1", force=False)
    volume = detach_cycle(image, volume, "unforced-2", force=False)
    volume = detach_cycle(image, volume, "forced-1", force=True)
    subprocess.run(
        ["/usr/bin/hdiutil", "detach", "-quiet", "-force", volume], check=False
    )
    subprocess.run(["rm", "-rf", directory], check=False)


main()
