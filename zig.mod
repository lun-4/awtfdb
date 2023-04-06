id: 2x7vkjjzn3aou7luwqy783uufl6iirnvswygghdhtmc8zd3s
name: awtfdb
license: MIT
description: The Anime Woman Tagged Files Database
root_dependencies:
  - src: git https://github.com/vrischmann/zig-sqlite branch-master
  - src: git https://github.com/lun-4/libpcre.zig branch-luna-pcre
  - src: git https://github.com/truemedian/hzzp
  - src: git https://github.com/lun-4/libmagic.zig
  - src: git https://github.com/lun-4/expiring-hash-map.zig
  - src: git https://github.com/lun-4/tunez branch-luna-stage2
    name: tunez
    main: src/main.zig
  - src: git https://github.com/lun-4/zig-ulid branch-no-alloc
