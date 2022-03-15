# prototype stage

import sys
import json
import subprocess
import shutil
import sqlite3
from pathlib import Path
from dataclasses import dataclass, field

import logging

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class Watcher:
    homedir: Path

    oldnames: dict = field(default_factory=dict)
    newnames: dict = field(default_factory=dict)
    rets: dict = field(default_factory=dict)

    def _resolve_renames(self):
        log.debug("%r %r %r", self.oldnames, self.newnames, self.rets)
        keys = list(self.rets.keys())
        for pid_tid_pair in keys:
            pid, tid = pid_tid_pair.split(",")
            return_value = self.rets.pop(pid_tid_pair)
            old_name = self.oldnames.pop(pid_tid_pair)
            new_name = self.newnames.pop(pid_tid_pair)

            if return_value == 0:
                log.debug(
                    "successful rename by %s: %s -> %s",
                    pid_tid_pair,
                    old_name,
                    new_name,
                )

                self._possibly_process_rename(pid, tid, old_name, new_name)

    def _possibly_process_rename(
        self, pid: str, tid: str, old_name: str, new_name: str
    ):
        try:
            cwd = Path(f"/proc/{pid}/cwd").resolve()
        except PermissionError:
            log.debug("%s is a process we cant access,ignoring rename", pid)
            return

        old_path = (cwd / old_name).resolve()
        new_path = (cwd / new_name).resolve()

        is_old_in_home = str(old_path).startswith(str(self.homedir))
        is_new_in_home = str(new_path).startswith(str(self.homedir))

        if not (is_old_in_home or is_new_in_home):
            log.debug(
                "%s is renaming to folder out of homedir (neither %s or %s is home)",
                pid,
                old_path,
                new_path,
            )
            return
        log.info("rename we care about (%s, %s, %s, %s)", pid, tid, old_path, new_path)

    def consume(self, stdout):
        while True:
            message = stdout.readline()
            for chunk in message.decode().split("\n"):
                if not chunk:
                    break

                if ":" not in chunk:
                    continue

                log.debug("received chunk %r", chunk)

                v1, type, pid, tid, *rest_data = chunk.split(":")
                data = ":".join(rest_data)
                # print(v1, type, pid, tid, data)

                if type == "oldname":
                    self.oldnames[f"{pid},{tid}"] = data
                if type == "newname":
                    self.newnames[f"{pid},{tid}"] = data
                if type == "ret":
                    self.rets[f"{pid},{tid}"] = int(data)
                    self._resolve_renames()


def main():
    try:
        homedir = Path(sys.argv[1]).resolve()
    except AttributeError:
        print(f"usage: {sys.argv[0]} <homedir>")
        return

    db = sqlite3.connect(homedir / "boorufs.db")

    proc = subprocess.Popen(
        [
            shutil.which("bpftrace"),
            "./rename_trace.bt",
        ],
        stdout=subprocess.PIPE,
    )
    log.info("running %r", proc.args)
    watcher = Watcher(homedir)
    try:
        watcher.consume(proc.stdout)
    finally:
        proc.terminate()
        db.close()


if __name__ == "__main__":
    main()
