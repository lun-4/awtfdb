#!/bin/sh
set -eux

zig build

./zig-out/bin/awtfdb-manage create
echo "among us" > among.txt
./zig-out/bin/ainclude -t amongi among.txt
afind_output=$(./zig-out/bin/afind amongi)
echo "$afind_output" | grep 'among.txt' -
