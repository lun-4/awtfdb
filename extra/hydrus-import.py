#!/usr/bin/env python3
# hydrus-import.sh - import hydrus exports into awtfdb
#
# hydrus has an export button! it's kinda cool, if you want to take your
# entire library out, select 'system:everything', right click until you
# find the export menu, select your wanted filename tag, and boom.
#
# written in python because shell is very, very weird on unicode filenames.
import sys
import os
import subprocess
import shlex
from pathlib import Path


def proper_tag(tag):
    return tag.replace(" ", "_")


def main():
    export_folder = Path(sys.argv[1])
    ainclude_extra_args = os.environ.get("AINCLUDE_ARGS", "")

    for filename in export_folder.glob("**/*"):
        print("processing", filename)
        tagpath = Path(str(filename) + ".txt")
        if not tagpath.exists():
            print("skip", filename, "no tag file")
            continue
        with tagpath.open(mode="r") as tagfile:
            tags = tagfile.read()
        tags = tags.split("\n")
        tag_args = [f"-t {shlex.quote(proper_tag(tag))}" for tag in tags if tag]
        tag_args_line = " ".join(tag_args)
        filename_escaped = shlex.quote(str(filename))
        cmdline = f"ainclude {ainclude_extra_args} {tag_args_line} {filename_escaped}"
        print("running", repr(cmdline))
        subprocess.check_output(cmdline, shell=True)


if __name__ == "__main__":
    main()
