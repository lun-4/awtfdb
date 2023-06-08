# extra tools for awtfdb

## tools to import data

`./hydrus-import.sh`: import a folder containing a hydrus export full of files
and their tag .txt files into the index.

## szurubooru web ui frontend

`./szurubooru-readonly-api.py`: visualize your awtfdb index using a szurubooru
frontend.

system dependencies:

- ffmpeg (`ffmpeg` and `ffprobe` commands)
- ghostscript (`gs` command)
- graphicsmagick (`gm` command)

in here, run

```
python3 -m pip install -Ur ./szurubooru-readonly-api.requirements.txt
python3 ./szurubooru-readonly-api.py
```

in another terminal, run

```
docker run --add-host=host.docker.internal:host-gateway -e BACKEND_HOST=host.docker.internal -p 6969:80 -it szurubooru/client:latest /docker-start.sh
```

then enter `localhost:6969` in your browser and watch the magic happen.

### szurubooru fast mode

requires nginx with the following block

```
server {
	listen 80;
	server_name home.example.net;
	location / {
		root /;
	}
}
```

and `/etc/hosts` with: `127.0.0.1  home.example.net  localhost`

then run the script with the following env var set `NGINX=home.example.net`
but the domain can be anything, it all just has to match

(if you use tailscale to share the booru across machines, set NGINX to the main
machine's tailscale ip, and set `server_name` to that same ip, things will
Just Work.)

## fuse frontend

```
pip install fuse-python
sudo mkdir /a
sudo chown $USER /a
python3 ./awtfdb-fuse.py -s -f /a
```

now you can `/a/@filehash` (e.g `/a/@69`) and you'll have a folder
containing a symbolic link to the original file in your filesystem.

TODO: support `/a/tag1/tag2/tag3` akin to supertag or afind(1).

## small but useful scripts

`./extra/find_duplicates.py`: find duplicate files and claimable space in your disk

`./extra/find_tag_typos.py`: find possible tag typos

`./extra/find_tag_parents.py`: find possible tag parenting relationships
