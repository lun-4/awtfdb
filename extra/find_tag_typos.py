#!/usr/bin/env python3

# pip install python-Levenshtein

import sys
import sqlite3
import logging
from pathlib import Path

log = logging.getLogger(__name__)

try:
    from Levenshtein import distance
except ImportError:
    raise ImportError("please run `pip install python-Levenshtein`")


def main():
    path = Path.home() / "awtf.db"
    db = sqlite3.connect(f"file:{str(path)}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    if len(sys.argv) >= 2:
        post_threshold = int(sys.argv[1])
    else:
        post_threshold = 0

    cur = db.cursor()

    res = cur.execute(
        """
        select tag_text, core_hash
        from tag_names
        """
    )
    tags = []
    for row in res:
        tags.append((row[0], row[1]))

    print(len(tags), "tags")

    for tag, core_hash in tags:
        scores = []

        metrics_count_res = cur.execute(
            """
            select relationship_count
            from metrics_tag_usage_values
            where core_hash = ?
            order by timestamp desc
            limit 1
            """,
            (core_hash,),
        )
        entry_row = metrics_count_res.fetchone()
        if not entry_row:
            log.info("tag %s has no metrics, calculating manually...", core_hash)

            full_count_res = cur.execute(
                "select count(core_hash) from tag_files where core_hash = ?",
                (core_hash,),
            )

            usages = full_count_res.fetchone()[0]
        else:
            usages = entry_row[0]

        if usages < post_threshold:
            continue

        scope = None
        if ":" in tag:
            scope, *_ = tag.split(":")

        for other_tag, _ in tags:
            if other_tag == tag:
                continue

            if len(other_tag) > (len(tag) + 3):
                continue

            if len(other_tag) < (len(tag) - 10):
                continue

            if scope and ":" in other_tag:
                other_scope, *_ = other_tag.split(":")

                if other_scope != scope:
                    continue

            score = distance(tag, other_tag)
            if score > len(tag):
                continue

            if score > 1:
                continue

            scores.append((other_tag, score))

        if not scores:
            continue

        sorted_scores = sorted(scores, key=lambda x: x[1])
        print(tag, sorted_scores[:10])


if __name__ == "__main__":
    sys.exit(main())
