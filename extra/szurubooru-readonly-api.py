import os
import shlex
import asyncio
import datetime
import re
import logging
import mimetypes
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass
from expiringdict import ExpiringDict

import magic
import aiosqlite
from quart import Quart, request, send_file as quart_send_file
from PIL import Image


log = logging.getLogger(__name__)
app = Quart(__name__)


async def send_file(path: str, *, mimetype: Optional[str] = None):
    """Helper function to send files while also supporting Ranged Requests."""
    response = await quart_send_file(path, mimetype=mimetype, conditional=True)

    filebody = response.response
    response.headers["content-length"] = filebody.end - filebody.begin
    response.headers["content-disposition"] = "inline"
    response.headers["content-security-policy"] = "sandbox; frame-src 'None'"

    return response


@dataclass
class FileCache:
    canvas_size: dict
    file_type: dict
    mime_type: dict
    local_path: dict


@dataclass
class TagEntry:
    name: str
    usages: int


@app.before_serving
async def app_before_serving():
    app.loop = asyncio.get_running_loop()
    indexpath = Path(os.getenv("HOME")) / "awtf.db"
    app.db = await aiosqlite.connect(str(indexpath))
    app.thumbnailing_tasks = {}
    app.expensive_thumbnail_semaphore = asyncio.Semaphore(3)
    app.image_thumbnail_semaphore = asyncio.Semaphore(10)
    app.file_cache = FileCache(
        canvas_size=ExpiringDict(max_len=10000, max_age_seconds=1200),
        file_type=ExpiringDict(max_len=10000, max_age_seconds=1200),
        mime_type=ExpiringDict(max_len=1000, max_age_seconds=300),
        local_path=ExpiringDict(max_len=1000, max_age_seconds=3600),
    )
    app.tag_cache = ExpiringDict(max_len=1000, max_age_seconds=300)


@app.after_serving
async def app_after_serving():
    await app.db.close()


@app.route("/info")
async def info():
    return {
        "postCount": 0,
        "diskUsage": 0,
        "featuredPost": None,
        "featuringTime": None,
        "featuringUser": None,
        "serverTime": datetime.datetime.utcnow().isoformat() + "Z",
        "config": {
            "userNameRegex": "^[a-zA-Z0-9_-]{1,32}$",
            "passwordRegex": "^.{5,}$",
            "tagNameRegex": "^\\S+$",
            "tagCategoryNameRegex": "^[^\\s%+#/]+$",
            "defaultUserRank": "administrator",
            "enableSafety": True,
            "contactEmail": None,
            "canSendMails": False,
            "privileges": {
                "users:create:self": "anonymous",
                "users:create:any": "administrator",
                "users:list": "regular",
                "users:view": "regular",
                "users:edit:any:name": "moderator",
                "users:edit:any:pass": "moderator",
                "users:edit:any:email": "moderator",
                "users:edit:any:avatar": "moderator",
                "users:edit:any:rank": "moderator",
                "users:edit:self:name": "regular",
                "users:edit:self:pass": "regular",
                "users:edit:self:email": "regular",
                "users:edit:self:avatar": "regular",
                "users:edit:self:rank": "moderator",
                "users:delete:any": "administrator",
                "users:delete:self": "regular",
                "userTokens:list:any": "administrator",
                "userTokens:list:self": "regular",
                "userTokens:create:any": "administrator",
                "userTokens:create:self": "regular",
                "userTokens:edit:any": "administrator",
                "userTokens:edit:self": "regular",
                "userTokens:delete:any": "administrator",
                "userTokens:delete:self": "regular",
                "posts:create:anonymous": "regular",
                "posts:create:identified": "regular",
                "posts:list": "anonymous",
                "posts:reverseSearch": "regular",
                "posts:view": "anonymous",
                "posts:view:featured": "anonymous",
                "posts:edit:content": "power",
                "posts:edit:flags": "regular",
                "posts:edit:notes": "regular",
                "posts:edit:relations": "regular",
                "posts:edit:safety": "power",
                "posts:edit:source": "regular",
                "posts:edit:tags": "regular",
                "posts:edit:thumbnail": "power",
                "posts:feature": "moderator",
                "posts:delete": "moderator",
                "posts:score": "regular",
                "posts:merge": "moderator",
                "posts:favorite": "regular",
                "posts:bulk-edit:tags": "power",
                "posts:bulk-edit:safety": "power",
                "tags:create": "regular",
                "tags:edit:names": "power",
                "tags:edit:category": "power",
                "tags:edit:description": "power",
                "tags:edit:implications": "power",
                "tags:edit:suggestions": "power",
                "tags:list": "regular",
                "tags:view": "anonymous",
                "tags:merge": "moderator",
                "tags:delete": "moderator",
                "tagCategories:create": "moderator",
                "tagCategories:edit:name": "moderator",
                "tagCategories:edit:color": "moderator",
                "tagCategories:edit:order": "moderator",
                "tagCategories:list": "anonymous",
                "tagCategories:view": "anonymous",
                "tagCategories:delete": "moderator",
                "tagCategories:setDefault": "moderator",
                "pools:create": "regular",
                "pools:edit:names": "power",
                "pools:edit:category": "power",
                "pools:edit:description": "power",
                "pools:edit:posts": "power",
                "pools:list": "regular",
                "pools:view": "anonymous",
                "pools:merge": "moderator",
                "pools:delete": "moderator",
                "poolCategories:create": "moderator",
                "poolCategories:edit:name": "moderator",
                "poolCategories:edit:color": "moderator",
                "poolCategories:list": "anonymous",
                "poolCategories:view": "anonymous",
                "poolCategories:delete": "moderator",
                "poolCategories:setDefault": "moderator",
                "comments:create": "regular",
                "comments:delete:any": "moderator",
                "comments:delete:own": "regular",
                "comments:edit:any": "moderator",
                "comments:edit:own": "regular",
                "comments:list": "regular",
                "comments:view": "regular",
                "comments:score": "regular",
                "snapshots:list": "power",
                "uploads:create": "regular",
                "uploads:useDownloader": "power",
            },
        },
    }


@app.errorhandler(400)
def handle_exception(exception):
    log.exception(f"Error in request: {exception!r}")
    return "shit", 400


@app.get("/tags/")
async def tags_fetch():
    # GET /tags/?offset=<initial-pos>&limit=<page-size>&query=<query>
    print(request.args)
    query = request.args["query"]
    query = query.replace("\\:", ":")
    offset = request.args.get("offset", 0)
    query = query.replace("*", "")
    query = query.replace(" sort:usages", "")
    tag_rows = await app.db.execute(
        """
    select distinct core_hash core_hash, hashes.hash_data
    from tag_names
    join hashes
    on hashes.id = tag_names.core_hash
    where tag_text LIKE '%' || ? || '%'
    """,
        (query,),
    )
    rows = []
    async for tag in tag_rows:
        tags = await fetch_tag(tag[0])
        for tag in tags:
            rows.append(
                {
                    "version": 1,
                    "names": tag["names"],
                    "category": "default",
                    "implications": [],
                    "suggestions": [],
                    "creationTime": "1900-01-01T00:00:00Z",
                    "lastEditTime": "1900-01-01T00:00:00Z",
                    "usages": tag["usages"],
                    "description": "awooga",
                }
            )

    return {
        "query": query,
        "offset": offset,
        "limit": 10000,
        "total": len(rows),
        "results": rows,
    }


@dataclass
class CompiledSearch:
    query: str
    tags: List[str]


def compile_query(search_query: str) -> CompiledSearch:
    or_operator = re.compile("( +)?\\|( +)?")
    not_operator = re.compile("( +)?-( +)?")
    and_operator = re.compile(" +")
    tag_regex = re.compile("[a-zA-Z-_0-9:;&\\*]+")
    raw_tag_regex = re.compile('".*?"')

    regexes = (
        or_operator,
        not_operator,
        and_operator,
        tag_regex,
        raw_tag_regex,
    )

    if not search_query:
        return CompiledSearch("select distinct file_hash from tag_files", [])

    final_query = ["select file_hash from tag_files where"]

    index = 0
    captured_regex_index = None
    tags = []

    while True:
        compiling_search_query = search_query[index:]
        if not compiling_search_query:
            break

        maybe_capture = None
        for regex_index, regex in enumerate(regexes):
            maybe_capture = regex.search(compiling_search_query)
            if maybe_capture and maybe_capture.start() == 0:
                captured_regex_index = regex_index
                break

        if maybe_capture:
            full_match = maybe_capture[0]
            index += maybe_capture.end()
            assert captured_regex_index is not None
            if captured_regex_index == 0:
                final_query.append(" or")
            if captured_regex_index == 1:
                if not tags:
                    final_query.append(" true")
                final_query.append(" except")
                final_query.append(" select file_hash from tag_files where")
            if captured_regex_index == 2:
                final_query.append(" intersect")
                final_query.append(" select file_hash from tag_files where")
            if captured_regex_index in (3, 4):
                final_query.append(" core_hash = ?")
                if captured_regex_index == 4:
                    full_match = full_match[1:-1]
                tags.append(full_match)

        else:
            raise Exception(f"Invalid search query. Unexpected character at {index}")
    return CompiledSearch("".join(final_query), tags)


def test_compiler():
    assert compile_query("a b c d") is not None
    result = compile_query('a b | "cd"|e')
    assert (
        result.query
        == "select file_hash from tag_files where core_hash = ? intersect select file_hash from tag_files where core_hash = ? or core_hash = ? or core_hash = ?"
    )
    assert result.tags == ["a", "b", "cd", "e"]


def test_compiler_batch():
    test_data = (
        ("a b c", ("a", "b", "c")),
        ("a bc d", ("a", "bc", "d")),
        ('a "bc" d', ("a", "bc", "d")),
        ('a "b c" d', ("a", "b c", "d")),
        ('a "b c" -d', ("a", "b c", "d")),
        ('-a "b c" d', ("a", "b c", "d")),
        ('-a -"b c" -d', ("a", "b c", "d")),
        ("-d", ("d",)),
    )

    for query, expected_tags_array in test_data:
        result = compile_query(query)
        assert result.tags == list(expected_tags_array)


def test_compiler_errors():
    import pytest

    with pytest.raises(Exception):
        compile_query('a "cd')


@app.get("/_awtfdb_content/<int:file_id>")
async def content(file_id: int):
    file_local_path = (
        await app.db.execute_fetchall(
            "select local_path from files where file_hash = ?",
            (file_id,),
        )
    )[0][0]
    return await send_file(file_local_path)


def blocking_thumbnail_image(path, thumbnail_path, size):
    with Image.open(path) as file_as_image:
        file_as_image.thumbnail(size)
        file_as_image.save(thumbnail_path)


async def thumbnail_given_path(path: Path, thumbnail_path: Path, size=(350, 350)):
    await app.loop.run_in_executor(
        None, blocking_thumbnail_image, path, thumbnail_path, size
    )


MIME_EXTENSION_MAPPING = {
    "video/x-matroska": ".mkv",
    "audio/x-m4a": ".m4a",
    "video/x-m4v": ".m4v",
    "video/3gpp": ".3gpp",
    "application/vnd.oasis.opendocument.text": ".odt",
    "application/epub+zip": ".epub",
}


def get_extension(mimetype):
    from_mimetypes = mimetypes.guess_extension(mimetype)
    if from_mimetypes:
        return from_mimetypes

    return MIME_EXTENSION_MAPPING[mimetype]


MIME_REMAPPING = {"video/x-matroska": "video/webm"}


def fetch_mimetype(file_path: str):
    mimetype = app.file_cache.mime_type.get(file_path)
    if not mimetype:
        mimetype = magic.from_file(file_path, mime=True)
        mimetype = MIME_REMAPPING.get(mimetype, mimetype)
        app.file_cache.mime_type[file_path] = mimetype
    return mimetype


async def thumbnail_given_video(file_local_path, thumbnail_path):
    proc = await asyncio.create_subprocess_shell(
        "ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1"
        f" {shlex.quote(file_local_path)}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    out, err = out.strip().decode(), err.decode()
    log.info("out: %r, err: %r", out, err)
    assert proc.returncode == 0

    total_seconds = int(float(out))
    total_5percent_seconds = total_seconds // 15

    proc = await asyncio.create_subprocess_shell(
        f"ffmpeg -n -i {shlex.quote(file_local_path)} "
        f"-ss {total_5percent_seconds} -frames:v 1 "
        f"{shlex.quote(str(thumbnail_path))}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    out, err = out.decode(), err.decode()
    log.info("out: %r, err: %r", out, err)
    assert proc.returncode == 0

    await thumbnail_given_path(str(thumbnail_path), str(thumbnail_path))


async def thumbnail_given_pdf(file_local_path, thumbnail_path):
    proc = await asyncio.create_subprocess_shell(
        f"gm convert {shlex.quote(file_local_path)} {shlex.quote(str(thumbnail_path))}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    out, err = out.decode(), err.decode()
    log.info("out: %r, err: %r", out, err)
    assert proc.returncode == 0

    await thumbnail_given_path(str(thumbnail_path), str(thumbnail_path), (600, 600))


async def _thumbnail_wrapper(semaphore, function, local_path, thumb_path):
    async with semaphore:
        await function(local_path, thumb_path)


async def submit_thumbnail(file_id, mimetype, file_local_path, thumbnail_path):
    if mimetype.startswith("image/"):
        thumbnailing_function = thumbnail_given_path
        semaphore = app.image_thumbnail_semaphore
    elif mimetype == ("application/pdf"):
        thumbnail_path = thumbnail_path.parent / f"{file_id}.png"
        semaphore = app.expensive_thumbnail_semaphore
        thumbnailing_function = thumbnail_given_pdf
    elif mimetype.startswith("video/"):
        thumbnail_path = thumbnail_path.parent / f"{file_id}.png"
        thumbnailing_function = thumbnail_given_video
        semaphore = app.expensive_thumbnail_semaphore
    else:
        return None

    if thumbnail_path.exists():
        return thumbnail_path

    task = app.thumbnailing_tasks.get(file_id)
    if not task:
        coro = _thumbnail_wrapper(
            semaphore, thumbnailing_function, file_local_path, thumbnail_path
        )
        task = app.loop.create_task(coro)
        app.thumbnailing_tasks[file_id] = task

    await asyncio.gather(task)
    try:
        app.thumbnailing_tasks.pop(file_id)
    except KeyError:
        pass
    return thumbnail_path


@app.get("/_awtfdb_thumbnails/<int:file_id>")
async def thumbnail(file_id: int):
    file_local_path = (
        await app.db.execute_fetchall(
            "select local_path from files where file_hash = ?",
            (file_id,),
        )
    )[0][0]

    mimetype = fetch_mimetype(file_local_path)
    extension = get_extension(mimetype)
    log.info("thumbnailing mime %s ext %r", mimetype, extension)
    assert extension is not None

    thumbnail_folder = Path("/tmp") / "awtfdb-szurubooru-thumbnails"
    thumbnail_folder.mkdir(exist_ok=True)
    thumbnail_path = thumbnail_folder / f"{file_id}{extension}"

    thumbnail_path = await submit_thumbnail(
        file_id, mimetype, file_local_path, thumbnail_path
    )
    if thumbnail_path:
        return await send_file(thumbnail_path)
    else:
        log.warning("cant thumbnail %s", mimetype)
        return "", 500


@app.get("/posts/")
async def posts_fetch():
    # GET /posts/?offset=<initial-pos>&limit=<page-size>&query=<query>
    # GET /tags/?offset=<initial-pos>&limit=<page-size>&query=<query>
    print(request.args)
    query = request.args.get("query", "")
    offset = int(request.args.get("offset", 0))
    limit = int(request.args.get("limit", 15))
    query = query.replace("\\:", ":")
    result = compile_query(query)
    mapped_tag_args = []
    for tag_name in result.tags:
        tag_name_cursor = await app.db.execute(
            """
        select hashes.id
        from tag_names
        join hashes
        on hashes.id = tag_names.core_hash
        where tag_text = ?
        """,
            (tag_name,),
        )

        tag_name_id = await tag_name_cursor.fetchone()
        if tag_name_id is None:
            raise Exception(f"tag not found {tag_name!r}")

        mapped_tag_args.append(tag_name_id[0])

    log.debug("query: %r", result.query)
    log.debug("tags: %r", result.tags)
    log.debug("mapped: %r", mapped_tag_args)
    tag_rows = await app.db.execute(
        result.query + f" limit {limit} offset {offset}",
        mapped_tag_args,
    )
    total_rows_count = await app.db.execute(
        result.query,
        mapped_tag_args,
    )
    total_files = len(await total_rows_count.fetchall())

    rows = []
    async for file_hash_row in tag_rows:
        file_hash = file_hash_row[0]
        rows.append(await fetch_file_entity(file_hash))

    return {
        "query": query,
        "offset": offset,
        "limit": limit,
        "total": total_files,
        "results": rows,
    }


def extract_canvas_size(path: Path) -> tuple:
    with Image.open(path) as im:
        return im.width, im.height


async def fetch_tag(core_hash):

    tag_entry = app.tag_cache.get(core_hash)
    if tag_entry is None:
        named_tag_cursor = await app.db.execute(
            """
            select tag_text
            from tag_names
            where tag_names.core_hash = ?
            """,
            (core_hash,),
        )

        usages_cursor = await app.db.execute(
            "select count(*) from tag_files where core_hash = ?",
            (core_hash,),
        )
        usages = (await usages_cursor.fetchone())[0]

        tag_entry = []
        async for named_tag in named_tag_cursor:
            tag_entry.append(TagEntry(named_tag[0], usages))

    assert tag_entry is not None
    app.tag_cache[core_hash] = tag_entry

    tags_result = []

    for named_tag in tag_entry:
        tags_result.append(
            {
                "names": [named_tag.name],
                "category": "default",
                "usages": named_tag.usages,
            }
        )

    return tags_result


async def fetch_file_entity(file_id: int) -> dict:
    file_tags = []

    file_tags_cursor = await app.db.execute(
        "select core_hash from tag_files where file_hash = ?",
        (file_id,),
    )
    async for core_hash in file_tags_cursor:
        tags = await fetch_tag(core_hash[0])
        file_tags.extend(tags)

    file_local_path = app.file_cache.local_path.get(file_id)
    if file_local_path is None:
        file_local_path = (
            await app.db.execute_fetchall(
                "select local_path from files where file_hash = ?",
                (file_id,),
            )
        )[0][0]
        app.file_cache.local_path[file_id] = file_local_path

    file_mime = fetch_mimetype(file_local_path)

    canvas_size = app.file_cache.canvas_size.get(file_id)
    file_type = app.file_cache.file_type.get(file_id)

    if canvas_size is None and file_mime.startswith("image/"):
        file_type = "image"
        if file_mime == "image/gif":
            file_type = "animation"
        canvas_size = await app.loop.run_in_executor(
            None, extract_canvas_size, file_local_path
        )
    elif canvas_size is None and file_mime.startswith("video/"):
        file_type = "video"
        proc = await asyncio.create_subprocess_shell(
            " ".join(
                [
                    "ffprobe",
                    "-v",
                    "error",
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "stream=width,height",
                    "-of",
                    "csv=s=x:p=0",
                    shlex.quote(file_local_path),
                ]
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        assert proc.returncode == 0
        out, err = out.decode().strip(), err.decode()
        log.info("out: %r, err: %r", out, err)
        canvas_size = out.split("x")
    elif canvas_size is None:
        canvas_size = (None, None)
        file_type = "image"

    assert len(canvas_size) == 2
    assert file_type in ("image", "animation", "video", "flash")
    app.file_cache.canvas_size[file_id] = canvas_size
    app.file_cache.file_type[file_id] = file_type

    return {
        "version": 1,
        "version": 1,
        "id": file_id,
        "creationTime": "1900-01-01T00:00:00Z",
        "lastEditTime": "1900-01-01T00:00:00Z",
        "safety": "safe",
        "source": None,
        "type": file_type,
        "checksum": "test",
        "checksumMD5": "test",
        "canvasWidth": int(canvas_size[0]) if canvas_size[0] else None,
        "canvasHeight": int(canvas_size[1]) if canvas_size[1] else None,
        "contentUrl": f"api/_awtfdb_content/{file_id}",
        "thumbnailUrl": f"api/_awtfdb_thumbnails/{file_id}",
        "flags": [],
        "tags": file_tags,
        "relations": [],
        "notes": [],
        "user": {"name": "root", "avatarUrl": None},
        "score": 0,
        "ownScore": 0,
        "ownFavorite": False,
        "tagCount": len(file_tags),
        "favoriteCount": 0,
        "commentCount": 0,
        "noteCount": 0,
        "featureCount": 0,
        "relationCount": 0,
        "lastFeatureTime": "1900-01-01T00:00:00Z",
        "favoritedBy": [],
        "hasCustomThumbnail": True,
        "mimeType": file_mime,
        "comments": [],
        "pools": [],
    }


@app.get("/post/<int:file_id>")
async def single_post_fetch(file_id: int):
    # GET /post/<id>
    return await fetch_file_entity(file_id)


@app.get("/post/<int:file_id>/around/")
async def single_post_fetch_around(file_id: int):
    # GET /post/<id>
    prev_cursor = await app.db.execute(
        """
        select file_hash
        from files
        where file_hash < ?
        order by file_hash desc
        limit 1
        """,
        (file_id,),
    )
    next_cursor = await app.db.execute(
        """
        select file_hash
        from files
        where file_hash > ?
        order by file_hash asc
        limit 1
        """,
        (file_id,),
    )
    prev_value = await prev_cursor.fetchone()
    prev_id = prev_value[0] if prev_value else None
    next_value = await next_cursor.fetchone()
    next_id = next_value[0] if next_value else None
    return {
        "prev": await fetch_file_entity(prev_id) if prev_id else None,
        "next": await fetch_file_entity(next_id) if next_id else None,
    }


@app.route("/tag-categories")
async def tag_categories():
    return {
        "results": [
            {
                "name": "default",
                "version": 1,
                "color": "default",
                "usages": 0,
                "default": True,
                "order": 1,
            }
        ],
    }


@app.route("/pool-categories")
async def pool_categories():
    return {
        "results": [
            {
                "name": "default",
                "version": 1,
                "color": "default",
                "usages": 0,
                "default": True,
            }
        ],
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(
        host="0.0.0.0",
        port=6666,
        debug=True,
    )
