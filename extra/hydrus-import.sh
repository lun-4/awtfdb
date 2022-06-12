#!/bin/sh
# hydrus-import.sh - import hydrus exports into awtfdb
#
# hydrus has an export button! it's kinda cool, if you want to take your
# entire library out, select 'system:everything', right click until you
# find the export menu, select your wanted filename tag, and boom.
#
# implemented in shell because that's easier instead of writing a full
# tag inferrer at the moment. maybe making one would be helpful in the long term.

set -eux

export_folder=$1
set +u
ainclude_extra_args=$AINCLUDE_ARGS
set -u

find "$export_folder" -type f |
while IFS= read -r filename; do
    echo "processing $filename";
    set +e
    tag_file_contents=$(cat "$filename.txt")
    if [ $? != "0" ]; then
        echo "$filename does not have matching tag file, ignoring"
        continue
    fi
    set -e
    ainclude_tags=$(echo "$tag_file_contents" | awk '{ printf "--tag \"%s\" ", $0; }')
    echo "$ainclude_tags '$filename'" | xargs ainclude $ainclude_extra_args
done
