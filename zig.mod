id: 2x7vkjjzn3aou7luwqy783uufl6iirnvswygghdhtmc8zd3s
name: awtfdb
license: MIT
description: The Anime Woman Tagged Files Database
root_dependencies:
  - src: git https://github.com/vrischmann/zig-sqlite branch-stage2
  - src: git https://github.com/kivikakk/libpcre.zig
  - src: git https://github.com/truemedian/hzzp
  #- src: git https://github.com/lun-4/libmagic-5.41 branch-luna-built-541
  - src: system_lib magic
  - src: git https://github.com/lun-4/expiring-hash-map.zig
  - src: git https://github.com/haze/tunez
    name: tunez
    main: src/main.zig
