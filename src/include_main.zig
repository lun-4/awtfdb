const std = @import("std");
const sqlite = @import("sqlite");
const manage_main = @import("main.zig");
const Context = manage_main.Context;
const tunez = @import("tunez");

const libpcre = @import("libpcre");

const log = std.log.scoped(.ainclude);

const VERSION = "0.0.1";
const HELPTEXT =
    \\ ainclude: include a file/folder into the awtfdb
    \\
    \\ usage:
    \\ 	ainclude [options..] <file/folder path...>
    \\
    \\ options:
    \\ 	-h				prints this help and exits
    \\ 	-V				prints version and exits
    \\ 	-v				turns on verbosity (debug logging)
    \\ 	-t <tag>, --tag <tag>			add the following tag to the given path
    \\ 					 (if its a folder, add the tag to all files in the folder)
    \\ 	--infer-tags <inferrer>		infer tags using a processor.
    \\					all tags after that argument shall be
    \\					processed using that inferrer's options,
    \\					if any of them don't match, then argument
    \\					processing comes back to normal options
    \\ 					 (available processors: regex)
    \\ --filter-indexed-files-only	only include files already indexed
    \\ 					(useful if you're moving files around
    \\ 					and they're not catched by the
    \\ 					rename watcher)
    \\
    \\ example, adding a single file:
    \\  ainclude --tag format:mp4 --tag "meme:what the dog doing" /downloads/funny_meme.mp4
    \\
    \\ example, adding a batch of files:
    \\  ainclude --tag format:mp4 --tag "meme:what the dog doing" /downloads/funny_meme.mp4 /download/another_dog_meme.mp4 /downloads/butter_dog.mp4
    \\
    \\ example, adding a media library:
    \\  ainclude --tag type:music --infer-tags media /my/music/collection
    \\
    \\ regex tag inferrer:
    \\ 	runs a regex over the filename of each included file and adds every
    \\ 	match as a tag for that file in the index.
    \\
    \\ 	every match group in the regex will be processed as a new tag
    \\
    \\ regex tag inferrer options:
    \\ 	--regex text			the regex to use (PCRE syntax)
    \\ 	--regex-use-full-path		if we should infer tags from the entire
    \\ 					path, instead of only the filename
    \\ 	--regex-text-scope scope	the tag scope to use (say, "mytag:")
    \\ 	--regex-cast-lowercase		if the content of the tag should be
    \\ 					converted to lowercase before adding it
    \\
    \\ example, using regex to infer tags based on filenames with "[tag]" as tags:
    \\  ainclude --infer-tags regex --regex '\[(.*?)\]' /my/movies/collection
;

fn utilAddScope(maybe_tag_scope: ?[]const u8, out: std.ArrayList(u8).Writer) !usize {
    if (maybe_tag_scope) |tag_scope| {
        return try out.write(tag_scope);
    } else {
        return 0;
    }
}

fn utilAddRawTag(config: anytype, raw_tag_text: []const u8, out: std.ArrayList(u8).Writer) !usize {
    if (config.cast_lowercase) {
        for (raw_tag_text) |raw_tag_character| {
            const written = try out.write(
                &[_]u8{std.ascii.toLower(raw_tag_character)},
            );
            std.debug.assert(written == 1);
        }
    } else {
        const written = try out.write(raw_tag_text);
        std.debug.assert(written == raw_tag_text.len);
    }

    return raw_tag_text.len;
}

const TestUtil = struct {
    pub fn runTestInferrerFile(
        allocator: std.mem.Allocator,
        filename: []const u8,
        test_vector_bytes: []const u8,
        comptime InferrerType: type,
        first_args: anytype,
        wanted_tags: anytype,
    ) !void {
        const ctx = first_args.@"1";
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();

        var file = try tmp.dir.createFile(filename, .{});
        defer file.close();
        _ = try file.write(test_vector_bytes);

        var indexed_file = try ctx.createFileFromDir(tmp.dir, filename);
        defer indexed_file.deinit();

        const hashlist = try indexed_file.fetchTags(allocator);
        defer allocator.free(hashlist);
        try std.testing.expectEqual(@as(usize, 0), hashlist.len);

        // actually run inferrer

        try @call(.{}, InferrerType.run, first_args ++ .{&indexed_file});

        const hashlist_after = try indexed_file.fetchTags(allocator);
        defer allocator.free(hashlist_after);
        try std.testing.expectEqual(@as(usize, wanted_tags.len), hashlist_after.len);

        var found_tags: [wanted_tags.len]bool = undefined;
        // initialize
        for (found_tags) |_, idx| found_tags[idx] = false;

        for (hashlist_after) |tag_core| {
            const tag_list = try ctx.fetchTagsFromCore(allocator, tag_core);
            defer tag_list.deinit();

            try std.testing.expectEqual(@as(usize, 1), tag_list.items.len);
            const tag = tag_list.items[0];
            try std.testing.expectEqual(tag_core.id, tag.core.id);
            inline for (wanted_tags) |wanted_tag, index| {
                if (std.mem.eql(u8, wanted_tag, tag.kind.Named.text)) {
                    found_tags[index] = true;
                }
            }
        }

        // assert its all true

        for (found_tags) |value| try std.testing.expect(value);
    }
};

const TagInferrer = enum {
    regex,
    audio,
};

const TagInferrerConfig = struct {
    last_argument: []const u8,
    config: union(TagInferrer) {
        regex: RegexTagInferrer.Config,
        audio: AudioMetadataTagInferrer.Config,
    },
};

const TagInferrerContext = union(TagInferrer) {
    regex: RegexTagInferrer.RunContext,
    audio: AudioMetadataTagInferrer.RunContext,
};

const RegexTagInferrer = struct {
    pub const Config = struct {
        text: ?[]const u8 = null,
        use_full_path: bool = false,
        tag_scope: ?[]const u8 = null,
        cast_lowercase: bool = false,
    };

    pub const RunContext = struct {
        allocator: std.mem.Allocator,
        config: Config,
        regex_cstr: [:0]const u8,
        regex: libpcre.Regex,
    };

    pub fn consumeArguments(args_it: *std.process.ArgIterator) !TagInferrerConfig {
        var arg_state: enum { None, Text, TagScope } = .None;
        var config: TagInferrerConfig = .{ .last_argument = undefined, .config = .{ .regex = .{} } };
        var arg: []const u8 = undefined;
        while (args_it.next()) |arg_from_loop| {
            arg = arg_from_loop;
            log.debug("(regex tag inferrer) state: {} arg: {s}", .{ arg_state, arg });

            switch (arg_state) {
                .None => {},
                .Text => config.config.regex.text = arg,
                .TagScope => config.config.regex.tag_scope = arg,
            }

            // if we hit non-None states, we need to know if we're going
            // to have another configuration parameter or not
            //
            // and we do this by next()'ing into the next argument
            if (arg_state != .None) {
                arg = args_it.next() orelse break;
                arg_state = .None;
            }
            log.debug("(regex tag inferrer, main loop) state: {s} arg: {s}", .{ arg_state, arg });

            if (std.mem.eql(u8, arg, "--regex")) {
                arg_state = .Text;
            } else if (std.mem.eql(u8, arg, "--regex-text-scope")) {
                arg_state = .TagScope;
            } else if (std.mem.eql(u8, arg, "--regex-cast-lowercase")) {
                config.config.regex.cast_lowercase = true;
            } else if (std.mem.eql(u8, arg, "--regex-use-full-path")) {
                config.config.regex.use_full_path = true;
            } else {
                config.last_argument = arg;
                break;
            }
        }

        if (config.config.regex.text == null) return error.RegexArgumentRequired;
        return config;
    }

    pub fn init(config: TagInferrerConfig, allocator: std.mem.Allocator) !RunContext {
        const regex_config = config.config.regex;
        const regex_cstr = try std.cstr.addNullByte(allocator, regex_config.text.?);
        return RunContext{
            .allocator = allocator,
            .config = regex_config,
            .regex_cstr = regex_cstr,
            .regex = try libpcre.Regex.compile(regex_cstr, .{}),
        };
    }

    pub fn deinit(self: *RunContext) void {
        self.allocator.free(self.regex_cstr);
    }

    pub fn run(self: *RunContext, ctx: *Context, file: *Context.File) !void {
        const basename = if (self.config.use_full_path) file.local_path else std.fs.path.basename(file.local_path);

        var offset: usize = 0;
        while (true) {
            var maybe_captures = try self.regex.captures(self.allocator, basename[offset..], .{});

            if (maybe_captures) |captures| {
                defer self.allocator.free(captures);

                const full_match = captures[0].?;
                for (captures[1..]) |capture| {
                    const tag_group = capture.?;

                    const raw_tag_text = basename[offset + tag_group.start .. offset + tag_group.end];
                    var tag_text_list = std.ArrayList(u8).init(self.allocator);
                    defer tag_text_list.deinit();

                    if (self.config.tag_scope) |tag_scope| {
                        const written = try tag_text_list.writer().write(tag_scope);
                        std.debug.assert(written == tag_scope.len);
                    }
                    if (self.config.cast_lowercase) {
                        for (raw_tag_text) |raw_tag_character| {
                            const written = try tag_text_list.writer().write(&[_]u8{std.ascii.toLower(raw_tag_character)});
                            std.debug.assert(written == 1);
                        }
                    } else {
                        const written = try tag_text_list.writer().write(raw_tag_text);
                        std.debug.assert(written == raw_tag_text.len);
                    }

                    const tag_text = tag_text_list.items;
                    log.info("found tag: {s}", .{tag_text});
                    var maybe_tag = try ctx.fetchNamedTag(tag_text, "en");
                    if (maybe_tag) |tag| {
                        try file.addTag(tag.core);
                    } else {
                        var tag = try ctx.createNamedTag(tag_text, "en", null);
                        try file.addTag(tag.core);
                    }
                }

                offset += full_match.end;
            } else {
                break;
            }
        }
    }
};

test "regex tag inferrer" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    // setup regex inferrer

    const regex_config = RegexTagInferrer.Config{
        .text = "\\[(.*?)\\]",
    };

    const allocator = std.testing.allocator;

    var context = try RegexTagInferrer.init(
        .{ .last_argument = undefined, .config = .{ .regex = regex_config } },
        allocator,
    );
    defer RegexTagInferrer.deinit(&context);

    try TestUtil.runTestInferrerFile(
        allocator,
        "test_[tag3] file [tag1] [tag2][tag4]",
        "awooga",
        RegexTagInferrer,
        .{ &context, &ctx },
        .{ "tag1", "tag2", "tag3", "tag4" },
    );
}

const AudioMetadataTagInferrer = struct {
    pub const Config = struct {
        tag_scope_album: ?[]const u8 = null,
        tag_scope_artist: ?[]const u8 = null,
        tag_scope_title: ?[]const u8 = null,
        cast_lowercase: bool = false,
    };

    pub const RunContext = struct {
        allocator: std.mem.Allocator,
        config: Config,
    };

    pub fn consumeArguments(args_it: *std.process.ArgIterator) !TagInferrerConfig {
        var arg_state: enum { None, AlbumTagScope, ArtistTagScope, TitleTagScope } = .None;
        var config: TagInferrerConfig = .{
            .last_argument = undefined,
            .config = .{ .audio = .{} },
        };
        var arg: []const u8 = undefined;
        while (args_it.next()) |arg_from_loop| {
            arg = arg_from_loop;
            log.debug("(audio tag inferrer) state: {} arg: {s}", .{ arg_state, arg });

            switch (arg_state) {
                .None => {},
                .AlbumTagScope => config.config.audio.tag_scope_album = arg,
                .ArtistTagScope => config.config.audio.tag_scope_artist = arg,
                .TitleTagScope => config.config.audio.tag_scope_title = arg,
            }

            // if we hit non-None states, we need to know if we're going
            // to have another configuration parameter or not
            //
            // and we do this by next()'ing into the next argument
            if (arg_state != .None) {
                arg = args_it.next() orelse break;
                arg_state = .None;
            }
            log.debug("(audio tag inferrer, main loop) state: {s} arg: {s}", .{ arg_state, arg });

            if (std.mem.eql(u8, arg, "--artist-tag-scope")) {
                arg_state = .ArtistTagScope;
            } else if (std.mem.eql(u8, arg, "--album-tag-scope")) {
                arg_state = .AlbumTagScope;
            } else if (std.mem.eql(u8, arg, "--title-tag-scope")) {
                arg_state = .TitleTagScope;
            } else if (std.mem.eql(u8, arg, "--cast-lowercase")) {
                config.config.regex.cast_lowercase = true;
            } else {
                config.last_argument = arg;
                break;
            }
        }

        return config;
    }

    pub fn init(config: TagInferrerConfig, allocator: std.mem.Allocator) !RunContext {
        return RunContext{
            .allocator = allocator,
            .config = config.config.audio,
        };
    }

    pub fn deinit(self: *RunContext) void {
        _ = self;
    }

    pub fn run(self: *RunContext, ctx: *Context, file: *Context.File) !void {
        var file_fd = try std.fs.cwd().openFile(file.local_path, .{ .mode = .read_only });
        defer file_fd.close();

        var buffered_reader = std.io.bufferedReader(file_fd.reader());

        var audio_meta = try tunez.resolveId3(buffered_reader.reader(), self.allocator);
        defer audio_meta.deinit();

        var tags_to_add = std.ArrayList([]const u8).init(self.allocator);
        defer tags_to_add.deinit();

        var string_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer string_arena.deinit();

        var string_pool_arena = string_arena.allocator();

        var string_pool = std.ArrayList(u8).init(self.allocator);
        defer string_pool.deinit();

        if (audio_meta.maybe_track_album) |album_name| {
            const start_index: usize = string_pool.items.len;
            var end_index: usize = start_index;
            end_index += try utilAddScope(self.config.tag_scope_album, string_pool.writer());
            end_index += try utilAddRawTag(self.config, album_name, string_pool.writer());
            try tags_to_add.append(try string_pool_arena.dupe(u8, string_pool.items[start_index..end_index]));
        }

        if (audio_meta.maybe_track_title) |title_name| {
            const start_index: usize = string_pool.items.len;
            var end_index: usize = start_index;
            end_index += try utilAddScope(self.config.tag_scope_title, string_pool.writer());
            end_index += try utilAddRawTag(self.config, title_name, string_pool.writer());
            try tags_to_add.append(try string_pool_arena.dupe(u8, string_pool.items[start_index..end_index]));
        }

        if (audio_meta.maybe_track_artists) |artists| {
            for (artists) |artist_name| {
                const start_index: usize = string_pool.items.len;
                var end_index: usize = start_index;
                end_index += try utilAddScope(self.config.tag_scope_artist, string_pool.writer());
                end_index += try utilAddRawTag(self.config, artist_name, string_pool.writer());
                try tags_to_add.append(try string_pool_arena.dupe(u8, string_pool.items[start_index..end_index]));
            }
        }

        for (tags_to_add.items) |named_tag_text| {
            log.info("audio: inferred tag {s}", .{named_tag_text});
            var maybe_tag = try ctx.fetchNamedTag(named_tag_text, "en");
            if (maybe_tag) |tag| {
                try file.addTag(tag.core);
            } else {
                var tag = try ctx.createNamedTag(named_tag_text, "en", null);
                try file.addTag(tag.core);
            }
        }
    }
};

const AUDIO_TEST_VECTORS = .{
    "test_vectors/audio_test_vector.mp3",
};

test "audio tag inferrer" {
    var ctx = try manage_main.makeTestContext();
    defer ctx.deinit();

    inline for (AUDIO_TEST_VECTORS) |test_vector_path| {
        std.log.warn("testing {s}", .{test_vector_path});
        const test_vector_bytes = @embedFile(test_vector_path);

        // TODO clean impl between RegexTagInferrer and AudioMetadataTagInferrer

        // setup audio inferrer

        const config = AudioMetadataTagInferrer.Config{
            .tag_scope_album = "album:",
            .tag_scope_artist = "artist:",
            .tag_scope_title = "title:",
        };
        const allocator = std.testing.allocator;

        var context = try AudioMetadataTagInferrer.init(
            .{ .last_argument = undefined, .config = .{ .audio = config } },
            allocator,
        );
        defer AudioMetadataTagInferrer.deinit(&context);

        // setup test file

        try TestUtil.runTestInferrerFile(
            allocator,
            "test.mp3",
            test_vector_bytes,
            AudioMetadataTagInferrer,
            .{ &context, &ctx },
            .{ "artist:Test Artist", "album:Test Album", "title:Test Track" },
        );
    }
}

pub fn main() anyerror!void {
    const rc = sqlite.c.sqlite3_config(sqlite.c.SQLITE_CONFIG_LOG, manage_main.sqliteLog, @as(?*anyopaque, null));
    if (rc != sqlite.c.SQLITE_OK) {
        std.log.err("failed to configure: {d} '{s}'", .{
            rc, sqlite.c.sqlite3_errstr(rc),
        });
        return error.ConfigFail;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var args_it = std.process.args();
    _ = args_it.skip();

    const StringList = std.ArrayList([]const u8);
    const ConfigList = std.ArrayList(TagInferrerConfig);

    const Args = struct {
        help: bool = false,
        verbose: bool = false,
        version: bool = false,
        default_tags: StringList,
        wanted_inferrers: ConfigList,
        include_paths: StringList,
        filter_indexed_files_only: bool = false,

        pub fn deinit(self: *@This()) void {
            self.default_tags.deinit();
            self.wanted_inferrers.deinit();
            self.include_paths.deinit();
        }
    };

    const ArgState = enum { None, FetchTag, InferMoreTags };

    var state: ArgState = .None;

    var given_args = Args{
        .default_tags = StringList.init(allocator),
        .wanted_inferrers = ConfigList.init(allocator),
        .include_paths = StringList.init(allocator),
    };
    defer given_args.deinit();

    var arg: []const u8 = undefined;
    while (args_it.next()) |arg_from_loop| {
        arg = arg_from_loop;
        log.debug("state: {s} arg: {s}", .{ state, arg });
        switch (state) {
            .FetchTag => {
                try given_args.default_tags.append(arg);
                state = .None;
                continue;
            },
            .InferMoreTags => {
                const tag_inferrer = std.meta.stringToEnum(TagInferrer, arg) orelse return error.InvalidTagInferrer;
                var inferrer_config = switch (tag_inferrer) {
                    .regex => try RegexTagInferrer.consumeArguments(&args_it),
                    .audio => try AudioMetadataTagInferrer.consumeArguments(&args_it),
                };

                try given_args.wanted_inferrers.append(inferrer_config);

                arg = inferrer_config.last_argument;
                state = .None;
            },
            .None => {},
        }
        log.debug("(possible transition) state: {s} arg: {s}", .{ state, arg });

        if (std.mem.eql(u8, arg, "-h")) {
            given_args.help = true;
        } else if (std.mem.eql(u8, arg, "-v")) {
            given_args.verbose = true;
        } else if (std.mem.eql(u8, arg, "-V")) {
            given_args.version = true;
        } else if (std.mem.eql(u8, arg, "--filter-indexed-files-only")) {
            given_args.filter_indexed_files_only = true;
        } else if (std.mem.eql(u8, arg, "--tag") or std.mem.eql(u8, arg, "-t")) {
            state = .FetchTag;
            // tag inferrers require more than one arg, so we need to load
            // those args beforehand and then pass the arg state forward
        } else if (std.mem.eql(u8, arg, "--infer-tags")) {
            state = .InferMoreTags;
            // TODO check if this is supposed to be an argument or an
            // actual option by peeking over args_it. paths can have --
            // after all.
        } else if (std.mem.startsWith(u8, arg, "--")) {
            return error.InvalidArgument;
        } else {
            try given_args.include_paths.append(arg);
        }
    }

    if (given_args.help) {
        std.debug.print(HELPTEXT, .{});
        return;
    } else if (given_args.version) {
        std.debug.print("ainclude {s}\n", .{VERSION});
        return;
    }

    if (given_args.verbose) {
        std.debug.todo("aa");
    }

    if (given_args.include_paths.items.len == 0) {
        std.log.err("at least one include path needs to be given", .{});
        return error.MissingArgument;
    }

    var ctx = Context{
        .home_path = null,
        .args_it = undefined,
        .stdout = undefined,
        .db = null,
        .allocator = allocator,
    };
    defer ctx.deinit();

    try ctx.loadDatabase(.{});

    std.log.info("args: {}", .{given_args});

    // map tag names to their relevant cores in db
    var default_tag_cores = Context.HashList.init(allocator);
    defer default_tag_cores.deinit();
    for (given_args.default_tags.items) |named_tag_text| {
        const maybe_tag = try ctx.fetchNamedTag(named_tag_text, "en");
        if (maybe_tag) |tag| {
            log.debug(
                "tag '{s}' is core {s}",
                .{ named_tag_text, tag.core },
            );
            try default_tag_cores.append(tag.core);
        } else {
            // TODO support ISO 639-2
            var new_tag = try ctx.createNamedTag(named_tag_text, "en", null);
            log.debug(
                "(created!) tag '{s}' with core {s}",
                .{ named_tag_text, new_tag.core },
            );
            try default_tag_cores.append(new_tag.core);
        }
    }

    var contexts = std.ArrayList(TagInferrerContext).init(allocator);
    defer contexts.deinit();
    for (given_args.wanted_inferrers.items) |inferrer_config| {
        switch (inferrer_config.config) {
            .regex => try contexts.append(.{ .regex = try RegexTagInferrer.init(inferrer_config, allocator) }),
            .audio => try contexts.append(.{ .audio = try AudioMetadataTagInferrer.init(inferrer_config, allocator) }),
        }
    }
    defer for (contexts.items) |*context| switch (context.*) {
        .regex => |*regex_ctx| RegexTagInferrer.deinit(regex_ctx),
        .audio => |*audio_ctx| AudioMetadataTagInferrer.deinit(audio_ctx),
    };

    for (given_args.include_paths.items) |path_to_include| {
        var dir: ?std.fs.Dir = std.fs.cwd().openDir(path_to_include, .{ .iterate = true }) catch |err| blk: {
            if (err == error.NotDir) break :blk null;
            log.err("error while including path '{s}': {s}", .{ path_to_include, @errorName(err) });
            return err;
        };
        defer if (dir) |*unpacked_dir| unpacked_dir.close();

        if (dir == null) {
            if (given_args.filter_indexed_files_only)
                std.debug.todo("TODO support filter_indexed_files_only on file paths");
            var file = try ctx.createFileFromPath(path_to_include);
            defer file.deinit();
            log.debug("adding file '{s}'", .{file.local_path});

            var savepoint = try ctx.db.?.savepoint("tags");
            errdefer savepoint.rollback();
            defer savepoint.commit();

            for (default_tag_cores.items) |tag_core| {
                try file.addTag(tag_core);
            }

            for (given_args.wanted_inferrers.items) |inferrer_config, index| {
                log.info("found config for  {}", .{inferrer_config});
                var inferrer_ctx = &contexts.items[index];
                switch (inferrer_ctx.*) {
                    .regex => |*regex_ctx| try RegexTagInferrer.run(regex_ctx, &ctx, &file),
                    .audio => |*audio_ctx| try AudioMetadataTagInferrer.run(audio_ctx, &ctx, &file),
                }
            }
        } else {
            var walker = try dir.?.walk(allocator);
            defer walker.deinit();

            while (try walker.next()) |entry| {
                switch (entry.kind) {
                    .File, .SymLink => {
                        log.debug(
                            "adding child path '{s}{s}{s}'",
                            .{ path_to_include, std.fs.path.sep_str, entry.path },
                        );

                        // if we only want to reindex files already in
                        // the system, hash them first and try to fetch the file
                        // if it exists, move forward, if not, skip that file
                        if (given_args.filter_indexed_files_only) {
                            var fs_file = try entry.dir.openFile(
                                entry.basename,
                                .{ .mode = .read_only },
                            );
                            defer fs_file.close();

                            const hash = try ctx.calculateHash(fs_file, .{ .insert_new_hash = false });
                            log.debug("hash is {s}", .{hash});
                            const maybe_file = try ctx.fetchFileByHash(hash.hash_data);

                            if (maybe_file) |file| {
                                file.deinit();
                            } else {
                                log.debug("skipping due to selected filter", .{});
                                continue;
                            }
                        }

                        var file = try ctx.createFileFromDir(entry.dir, entry.basename);
                        defer file.deinit();
                        {
                            var savepoint = try ctx.db.?.savepoint("tags");
                            errdefer savepoint.rollback();
                            defer savepoint.commit();

                            for (default_tag_cores.items) |tag_core| {
                                try file.addTag(tag_core);
                            }

                            for (given_args.wanted_inferrers.items) |inferrer_config, index| {
                                log.info("found config for  {}", .{inferrer_config});
                                var inferrer_ctx = &contexts.items[index];
                                switch (inferrer_ctx.*) {
                                    .regex => |*regex_ctx| try RegexTagInferrer.run(regex_ctx, &ctx, &file),
                                    .audio => |*audio_ctx| try AudioMetadataTagInferrer.run(audio_ctx, &ctx, &file),
                                }
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }
}
