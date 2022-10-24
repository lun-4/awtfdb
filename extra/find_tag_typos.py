#!/usr/bin/env python3

# pip install python-Levenshtein

import sys
import sqlite3
from pathlib import Path
from Levenshtein import distance


def main():
    path = Path.home() / "awtf.db"
    db = sqlite3.connect(f"file:{str(path)}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row

    cur = db.cursor()

    res = cur.execute(
        """
        select tag_text
        from tag_names
        """
    )
    tags = []
    for row in res:
        tags.append(row[0])

    print(len(tags), "tags")

    for tag in tags:
        scores = []

        scope = None
        if ":" in tag:
            scope, *_ = tag.split(":")

        for other_tag in tags:
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
