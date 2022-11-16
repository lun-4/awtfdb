#!/usr/bin/env python3


import sys
import sqlite3
from pathlib import Path
from collections import Counter


def main():
    path = Path.home() / "awtf.db"
    db = sqlite3.connect(f"file:{str(path)}?mode=ro", uri=True)

    cur = db.cursor()

    res = cur.execute(
        """
        select tag_text, core_hash
        from tag_names
        """,
    )
    for row in res:
        tag_text, tag_id = row

        files_cursor = db.execute(
            """
            select file_hash
            from tag_files
            where core_hash = ?
            """,
            (tag_id,),
        )
        counter = Counter()
        for file_hash_row in files_cursor:
            file_hash = file_hash_row[0]
            tags_in_file_cursor = db.execute(
                """
                select core_hash
                from tag_files
                where file_hash = ? and not (core_hash = ?)
                """,
                (file_hash, tag_id),
            )
            for tag in tags_in_file_cursor:
                counter[tag[0]] += 1

        tags = []
        for core_hash, count in counter.most_common(10):
            tag_text_cursor = db.execute(
                """
                select tag_text
                from tag_names
                where core_hash = ?
                """,
                (core_hash,),
            )
            common_tag_text = tag_text_cursor.fetchone()[0]
            tags.append((common_tag_text, count))

        line = f"{tag_text} -> {', '.join(tag_text for tag_text,count in tags)}"
        print(line)


if __name__ == "__main__":
    sys.exit(main())
