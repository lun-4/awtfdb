#!/bin/sh

set -eux

runit() {
    ln -s $(realpath ./installation/runit/awtfdb-watcher) /var/service/
}

runit
