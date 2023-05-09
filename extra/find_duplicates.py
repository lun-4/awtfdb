#!/usr/bin/env python3

import sys
import sqlite3
from pathlib import Path


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
    filemap = {}
    sizemap = {}
    total_space = 0
    for row in res:
        if row["file_hash"] not in filemap:
            filemap[row["file_hash"]] = [row["local_path"]]
        else:
            filemap[row["file_hash"]].append(row["local_path"])

        if row["file_hash"] not in sizemap:
            stats = Path(row["local_path"]).stat()
            sizemap[row["file_hash"]] = stats.st_size

        total_space += sizemap[row["file_hash"]]

    sorted_keys = sorted(sizemap.keys(), key=lambda k: sizemap[k])
    claimable_space = 0
    for filehash in sorted_keys:
        size = sizemap[filehash]
        paths = filemap[filehash]
        claimable_space += size * (len(paths) - 1)
        size_mb = round(size / 1024 / 1024, 2)

        print(f"file {filehash}, size {size_mb} MB")
        for path in paths:
            print(f"\t{path}")

    total_space_mb = total_space // 1024 // 1024
    claimable_space_mb = claimable_space // 1024 // 1024

    print("total", total_space_mb, "MB")
    print("claimable", claimable_space_mb, "MB")


if __name__ == "__main__":
    sys.exit(main())
