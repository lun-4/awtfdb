#!/usr/bin/env python3

import sys
import sqlite3
from pathlib import Path
from typing import Dict, List


def main():
    path = Path.home() / "awtf.db"
    db = sqlite3.connect(f"file:{str(path)}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row

    cur = db.cursor()

    # TODO this should be probably rewritten as a CTE
    res = cur.execute(
        """
        select distinct
            file_hash,
            local_path,
            (select count(*) from files where file_hash = f1.file_hash) as repeated_count
        from files f1
        where
            repeated_count > 1
        order by
            repeated_count desc;
        """
    )
    filemap: Dict[str, List[str]] = {}
    single_size_map: Dict[str, int] = {}
    full_size_map: Dict[str, int] = {}

    for row in res:
        if row["file_hash"] not in filemap:
            filemap[row["file_hash"]] = [row["local_path"]]
        else:
            filemap[row["file_hash"]].append(row["local_path"])

    total_duplicate_files = 0

    for file_hash, paths in filemap.items():
        stat = Path(paths[0]).stat()
        full_size_map[file_hash] = stat.st_size * len(paths)
        single_size_map[file_hash] = stat.st_size
        total_duplicate_files += len(paths) - 1

    total_space = sum(full_size_map.values())

    sorted_keys = sorted(
        filemap.keys(), key=lambda k: full_size_map[k] - single_size_map[k]
    )
    claimable_space = 0
    for filehash in sorted_keys:
        full_size = full_size_map[filehash]
        single_size = single_size_map[filehash]
        paths = filemap[filehash]
        paths = sorted(paths, key=lambda path: Path(path).stat().st_mtime)
        claimable_size = full_size - single_size
        claimable_space += claimable_size
        full_size_mb = round(full_size / 1024 / 1024, 2)
        claimable_size_mb = round(claimable_size / 1024 / 1024, 2)

        print(
            f"file {filehash}, consumes {full_size_mb} MB ({claimable_size_mb}MB claimable)"
        )
        for path in paths:
            print(f"\t{path}")

    total_space_mb = total_space // 1024 // 1024
    claimable_space_mb = claimable_space // 1024 // 1024

    print(
        "there are",
        len(filemap),
        "duplicate entries (with more than one file in them)",
    )
    print("in total", total_duplicate_files, "duplicate files")

    print("total", total_space_mb, "MB")
    print("claimable", claimable_space_mb, "MB")


if __name__ == "__main__":
    sys.exit(main())
