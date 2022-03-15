# boorufs

(wip) a "many-compromises" file indexing system

NOT READY. DO NOT USE. NOT READY. DO NOT USE.

## inspiration

- hydrus
- booru-ware

## design notes

if i could make it a single phrase: boorufs is an incremental non-destructive tagging system for your life's files full of compromises.

you start it with 'boorufs path/to/home/directory', it'll create a sqlite file on homedir/boorufs.db, and run necessary migrations

then, say, you have a folder full of music. you can track them with 'binclude mediadir', but that'd just track them without tags. we know its a media directory, why not infer tags based on content?

'binclude --add-single-tag source:bandcamp --infer-media-tags mediadir/bd-dl'

artist:, title:, album:, and others get inferred from the id3 tags, if those arent provided, inferring from path is done (say, we know title is equal to filename)

you can take a look at the changes binclude will make, it'll always betch-add tags, never remove. if you find that its inferring is wrong for an album, ctrl-c/say no, and redo it ignoring that specific album

'binclude --add-single-tag source:bandcamp --infer-media-tags mediadir/bd-dl --exclude mediadir/bd-dl/album_with_zalgotext'

you can 'badd tag file' to add a single tag to a single file, or to a folder: 'badd -R tag folder'

'bstat path' to see file tags

'bfind <predicate>' to execute search across all files e.g 'bfind format:flac "artist:dj kuroneko"' to return all flacs made by dj kuroneko

## how

WIP.

## install

WIP.

## roadmap

WIP.
