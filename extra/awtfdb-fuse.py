#!/usr/bin/env python
#
# pip install fuse-python

import os
import errno
import stat
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Dict

import fuse


log = logging.getLogger(__name__)


@dataclass
class File:
    id: str

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return self.id == other.id

    @classmethod
    def from_part(cls, part):
        assert part.startswith("@")
        _, id = part.split("@")
        return cls(id)

    def fetch_paths(self, db) -> List[Path]:
        cursor = db.execute(
            "select local_path from files where file_hash = ?", (self.id,)
        )
        rows = cursor.fetchall()
        if rows:
            return [p for p in [Path(row[0]) for row in rows] if p.exists()]
        else:
            raise FileNotFoundError(f"file id not found ({self.id})")


@dataclass
class Pool:
    id: str

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return self.id == other.id

    @classmethod
    def from_part(cls, part):
        assert part.startswith("!")
        _, id = part.split("!")
        return cls(id)

    def fetch_paths(self, db, filename=None) -> List[Path]:
        cursor = db.execute(
            """
            select local_path
            from files
            join pool_entries
            on pool_entries.file_hash = files.file_hash
            where pool_entries.pool_hash = ?
            order by pool_entries.entry_index asc;
            """,
            (self.id,),
        )
        rows = cursor.fetchall()
        if rows:
            return [p for p in [Path(row[0]) for row in rows] if p.exists()]
        else:
            raise FileNotFoundError(f"pool id not found ({self.id})")


class FuseServer(fuse.Fuse):
    def __init__(self, *args, **kwargs):
        fuse.Fuse.__init__(self, *args, **kwargs)

        indexpath = Path(os.getenv("HOME")) / "awtf.db"
        self.db = sqlite3.connect(str(indexpath))
        self.local_path_cache: Dict[Tuple[str, str], str] = {}

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

    def to_local_path(self, vfs_path: Path) -> Tuple[bool, List[Path]]:
        possible_id = None

        try:
            fuse_request = vfs_path.parts[1]
        except IndexError:
            fuse_request = ""
        if fuse_request.startswith("@"):
            possible_id = File.from_part(fuse_request)
        elif fuse_request.startswith("!"):
            possible_id = Pool.from_part(fuse_request)
        else:
            raise FileNotFoundError(f"not any actionable request ({vfs_path!r})")

        assert possible_id
        wants_listing = len(vfs_path.parts) == 2
        if wants_listing:
            local_paths = possible_id.fetch_paths(self.db)
            return wants_listing, local_paths
        else:
            # we want a specific file, send only one.
            wanted_filename = vfs_path.parts[2]
            cached_value = self.local_path_cache.get((possible_id, vfs_path.name))
            if cached_value:
                return False, [cached_value]
            else:
                local_paths = possible_id.fetch_paths(self.db)
                for local_path in local_paths:
                    if local_path.name == wanted_filename:
                        cached_value = local_path
                    self.local_path_cache[(possible_id, local_path.name)] = local_path

            return False, [cached_value]

    def readlink(self, vfs_path):
        log.info("getattr req %r", vfs_path)
        try:
            wants_listing, local_paths = self.to_local_path(Path(vfs_path))
        except FileNotFoundError:
            return -errno.ENOENT

        if wants_listing:
            log.error("vfs %r not the final file", vfs_path)
            return -errno.ENOENT

        assert len(local_paths) == 1
        return str(local_paths[0])

    def getattr(self, vfs_path: str):
        if vfs_path == "/":  # make it work for root always (its a folder lol)
            return os.lstat("/")
        log.info("getattr req %r", vfs_path)

        vfs_path = Path(vfs_path)

        try:
            wants_listing, local_paths = self.to_local_path(vfs_path)
        except FileNotFoundError:
            return -errno.ENOENT

        log.info("getattr ok %r -> %r", vfs_path, local_paths)
        assert local_paths
        if not local_paths[0]:
            return -errno.ENOENT
        original_stat = os.lstat(local_paths[0])
        if wants_listing:
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
                    len(str(local_paths[0])),
                    original_stat.st_atime,
                    original_stat.st_mtime,
                    original_stat.st_ctime,
                ]
            )

            # log.info("old stat %r", stat)
            # log.info("new stat %r", new_stat)

            return new_stat
        else:
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
                    len(str(local_paths[0])),
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
            wants_listing, local_paths = self.to_local_path(Path(vfs_path))
        except FileNotFoundError:
            return -errno.ENOENT

        if wants_listing:
            for path in local_paths:
                yield fuse.Direntry(path.name)
        else:
            raise AssertionError("should not readdir from the symlink")

    def access(self, vfs_path, mode):
        try:
            _, local_paths = self.to_local_path(Path(vfs_path))
        except FileNotFoundError:
            return -errno.ENOENT

        for path in local_paths:
            if not os.access(path, mode):
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
