#!/usr/bin/env python
#
# pip install fuse-python

import os
import sys
import errno
import stat
import logging
import sqlite3
from pathlib import Path
from typing import Optional, Tuple

import fuse


log = logging.getLogger(__name__)


class FuseServer(fuse.Fuse):
    def __init__(self, *args, **kwargs):
        fuse.Fuse.__init__(self, *args, **kwargs)

        indexpath = Path(os.getenv("HOME")) / "awtf.db"
        self.db = sqlite3.connect(str(indexpath))

    def _fallback(self, field):
        def wrapped(*args, **kwargs):
            log.info("FALLBACK field %r %r %r", field, args, kwargs)

        return wrapped

    def __getattr__(self, field):
        FSOPS = [
            "getattr",
            "readlink",
            "readdir",
            "mknod",
            "mkdir",
            "unlink",
            "rmdir",
            "symlink",
            "rename",
            "link",
            "chmod",
            "chown",
            "truncate",
            "utime",
            "open",
            "read",
            "write",
            "release",
            "statfs",
            "fsync",
            "create",
            # "opendir",
            # "releasedir",
            # "fsyncdir",
            "flush",
            "fgetattr",
            "ftruncate",
            "getxattr",
            "listxattr",
            "setxattr",
            "removexattr",
            "access",
            "lock",
            "utimens",
            "bmap",
            "fsinit",
            "fsdestroy",
            "ioctl",
            "poll",
        ]

        try:
            return super().__getattr__(field)
        except AttributeError as exc:
            if field in FSOPS:
                return self._fallback(field)
            else:
                raise exc

    def statfs(self):
        return os.statvfs(".")

    def to_local_path(self, vfs_path: Path) -> Tuple[bool, Path]:
        possible_file_id = None
        for part in vfs_path.parts[:3]:
            if not part.startswith("@"):
                continue
            else:
                possible_file_id = part
                break

        wants_file = not vfs_path.parts[-1].startswith("@")

        if possible_file_id is None:
            raise FileNotFoundError(f"not a file ({vfs_path!r})")

        _, file_hash_str = possible_file_id.split("@")
        try:
            file_hash = str(file_hash_str)
        except ValueError:
            raise FileNotFoundError(f"invalid file id ({file_hash_str!r})")

        cur = self.db.execute(
            "select local_path from files where file_hash = ?", (file_hash,)
        )
        rows = cur.fetchall()
        if rows:
            return wants_file, Path(rows[0][0])
        else:
            raise FileNotFoundError(f"file id not found ({file_hash})")

    def readlink(self, vfs_path):
        log.info("getattr req %r", vfs_path)
        try:
            wants_file, local_path = self.to_local_path(Path(vfs_path))
        except FileNotFoundError:
            return -errno.ENOENT

        if not wants_file:
            log.error("vfs %r not the final file")
            return -errno.ENOENT

        return str(local_path)

    def getattr(self, vfs_path: str):
        if vfs_path == "/":  # make it work for root always (its a folder lol)
            return os.lstat("/")
        log.info("getattr req %r", vfs_path)

        vfs_path = Path(vfs_path)

        try:
            wants_file, local_path = self.to_local_path(vfs_path)
        except FileNotFoundError:
            return -errno.ENOENT

        log.info("getattr ok %r -> %r", vfs_path, local_path)
        original_stat = os.lstat(local_path)
        if wants_file:
            mode = original_stat.st_mode
            mode |= stat.S_IFLNK

            new_stat = os.stat_result(
                [
                    mode,
                    original_stat.st_ino,
                    original_stat.st_dev,
                    original_stat.st_nlink,
                    original_stat.st_uid,
                    original_stat.st_gid,
                    len(str(local_path)),
                    original_stat.st_atime,
                    original_stat.st_mtime,
                    original_stat.st_ctime,
                ]
            )

            # log.info("old stat %r", stat)
            # log.info("new stat %r", new_stat)

            return new_stat
        else:
            mode = 0
            mode |= stat.S_IFDIR
            mode |= stat.S_IRWXU
            mode |= stat.S_IRGRP
            mode |= stat.S_IXOTH

            new_stat = os.stat_result(
                [
                    mode,
                    original_stat.st_ino,
                    original_stat.st_dev,
                    original_stat.st_nlink,
                    original_stat.st_uid,
                    original_stat.st_gid,
                    len(str(local_path)),
                    original_stat.st_atime,
                    original_stat.st_mtime,
                    original_stat.st_ctime,
                ]
            )

            # log.info("old stat %r", stat)
            # log.info("new stat %r", new_stat)

            return new_stat

    def readdir(self, vfs_path, _offset):
        if vfs_path == "/":
            return

        log.info("readdir %r %r", vfs_path, _offset)

        try:
            wants_file, local_path = self.to_local_path(Path(vfs_path))
        except FileNotFoundError:
            return -errno.ENOENT

        if wants_file:
            raise AssertionError("should not readdir from the symlink")
        else:
            yield fuse.Direntry(local_path.name)

    def access(self, vfs_path, mode):
        try:
            _, local_path = self.to_local_path(Path(vfs_path))
        except FileNotFoundError:
            return -errno.ENOENT

        if not os.access(local_path, mode):
            return -errno.EACCES

    def fsinit(self):
        log.info("fsinit!")

    def fsdestroy(self):
        log.info("fsdestroy!")
        if self.db:
            self.db.close()

    def main(self, *args, **kwargs):
        log.info("main %r %r", args, kwargs)
        return fuse.Fuse.main(self, *args, **kwargs)


def main():
    fuse.fuse_python_api = (0, 2)
    fuse.feature_assert("stateful_files", "has_init", "has_destroy")
    logging.basicConfig(level=logging.DEBUG)

    usage = (
        """
        An awtfdb FUSE frontend.
        """
        + fuse.Fuse.fusage
    )

    server = FuseServer(
        version="%prog " + fuse.__version__, usage=usage, dash_s_do="setsingle"
    )
    server.parse(values=server, errex=1)
    server.main()


if __name__ == "__main__":
    main()
