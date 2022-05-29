import datetime
import re
import logging

from quart import Quart, request, send_file
import aiosqlite


log = logging.getLogger(__name__)
app = Quart(__name__)


@app.before_serving
async def app_before_serving():
    app.db = await aiosqlite.connect("/home/luna/awtf.db")


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

        named_tag_cursor = await app.db.execute(
            "select tag_text, tag_language from tag_names where core_hash = ?",
            (tag[0],),
        )

        namedtag = await named_tag_cursor.fetchone()

        filecount_cursor = await app.db.execute(
            "select count(*) from tag_files where core_hash = ?",
            (tag[0],),
        )
        filecount = (await filecount_cursor.fetchone())[0]

        rows.append(
            {
                "version": 1,
                "names": [namedtag[0]],
                "category": "default",
                "implications": [],
                "suggestions": [],
                "creationTime": "1900-01-01T00:00:00Z",
                "lastEditTime": "1900-01-01T00:00:00Z",
                "usages": filecount,
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


from dataclasses import dataclass
from typing import List


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


@app.get("/_awtfdb_thumbnails/<int:file_id>")
async def thumbnail(file_id: int):
    file_local_path = (
        await app.db.execute_fetchall(
            "select local_path from files where file_hash = ?",
            (file_id,),
        )
    )[0][0]
    return await send_file(file_local_path)


@app.get("/posts/")
async def posts_fetch():
    # GET /posts/?offset=<initial-pos>&limit=<page-size>&query=<query>
    # GET /tags/?offset=<initial-pos>&limit=<page-size>&query=<query>
    print(request.args)
    query = request.args["query"]
    offset = int(request.args.get("offset", 0))
    limit = int(request.args.get("limit", 15))
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
        mapped_tag_args.append((await tag_name_cursor.fetchone())[0])

    log.debug("query: %r", result.query)
    log.debug("tags: %r", result.tags)
    log.debug("mapped: %r", mapped_tag_args)
    tag_rows = await app.db.execute(
        result.query,
        mapped_tag_args,
    )

    rows = []
    async for file_hash_row in tag_rows:
        file_hash = file_hash_row[0]

        file_tags = []

        file_tags_cursor = await app.db.execute(
            "select core_hash from tag_files where file_hash = ?",
            (file_hash,),
        )
        async for core_hash in file_tags_cursor:
            named_tag_cursor = await app.db.execute(
                """
            select tag_text
            from tag_names
            where tag_names.core_hash = ?
            """,
                (core_hash[0],),
            )

            usages_cursor = await app.db.execute(
                "select count(*) from tag_files where core_hash = ?",
                (core_hash[0],),
            )
            usages = (await usages_cursor.fetchone())[0]

            async for named_tag in named_tag_cursor:
                file_tags.append(
                    {
                        "names": [named_tag[0]],
                        "category": "default",
                        "usages": usages,
                    }
                )

        rows.append(
            {
                "version": 1,
                "version": 1,
                "id": file_hash,
                "creationTime": "1900-01-01T00:00:00Z",
                "lastEditTime": "1900-01-01T00:00:00Z",
                "safety": "safe",
                "source": None,
                "type": "image",
                "checksum": "test",
                "checksumMD5": "test",
                "canvasWidth": 500,
                "canvasHeight": 500,
                "contentUrl": f"api/_awtfdb_content/{file_hash}",
                "thumbnailUrl": f"api/_awtfdb_thumbnails/{file_hash}",
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
                "mimeType": "image/png",
                "comments": [],
                "pools": [],
            }
        )

    return {
        "query": query,
        "offset": offset,
        "limit": 10000,
        "total": len(rows),
        "results": rows,
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
    app.run(
        host="0.0.0.0",
        port=6666,
        debug=True,
    )
