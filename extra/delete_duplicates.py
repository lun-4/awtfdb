#!/usr/bin/env python3
# use as follows
# 'python3 ./extra/find_duplicates.py --json | python3 ./extra/delete_duplicates.py'
#
# use find_duplicates to analyze the dataset, then delete_duplicates to actually
# remove them from the index and from the filesystem


import time
import pprint
import shlex
import shutil
import subprocess
import fileinput
import hashlib
import logging
import json
import sys
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

log = logging.getLogger(__name__)


def md5_hashes(file_path: Path) -> str:
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    assert file_path.is_file()
    with file_path.open(mode="rb") as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)

    return md5.hexdigest()


@dataclass
class Entry:
    file_hash: str
    consumes: int
    claimable: int
    paths: List[str]


def main():
    for line in fileinput.input(encoding="utf-8"):
        duplicate_entry_json = json.loads(line)
        assert duplicate_entry_json.pop("version") == 1
        entry = Entry(**duplicate_entry_json)
        assert len(entry.paths) > 1
        paths = [Path(p) for p in entry.paths]
        hashes = {md5_hashes(p) for p in paths}
        log.debug("processing %r", entry.file_hash)
        if len(hashes) != 1:
            print(f"WARNING INCORRECT STATE for {entry.file_hash} {hashes!r}")
            raise AssertionError("file hashes are inconsistent, aborting now")

        paths = sorted(paths, key=lambda path: Path(path).stat().st_mtime)
        original_path = paths[0]
        paths_to_delete = paths[1:]
        assert len(paths_to_delete) > 0
        assert original_path not in paths_to_delete
        log.debug("deleting paths %s", pprint.pformat(paths_to_delete))
        log.debug("NOT DELETING %s", original_path)
        claimed_space = 0
        for path in paths_to_delete:
            args = [shutil.which("arm"), str(path.resolve())]
            log.debug("running %r", args)
            proc = subprocess.Popen(
                args, stderr=subprocess.PIPE, stdout=subprocess.PIPE
            )
            proc.wait()
            log.debug("exitcode: %d", proc.returncode)
            log.debug("stdout: %r", proc.stdout.read())
            log.debug("stderr: %r", proc.stderr.read())
            assert proc.returncode == 0
            claimed_space += path.stat().st_size
            path.unlink()
            # dont delete the single copy we'll have of this file lmao
            assert original_path.exists()

        # DONT
        assert original_path.exists()

        claimed_space_mb = claimed_space / 1024 / 1024
        log.info("deleted %.2fMB", claimed_space_mb)

        # really, DONT
        assert original_path.exists()

        # give some time for user to see things in action
        time.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    sys.exit(main())
