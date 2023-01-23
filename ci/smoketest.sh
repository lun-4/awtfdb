#!/bin/sh
set -eux

zig build

./zig-out/bin/awtfdb-manage create
