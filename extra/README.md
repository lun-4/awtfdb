# extra tools for awtfdb

`./hydrus-import.sh`: import a folder containing a hydrus export full of files
and their tag .txt files into the index.

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
