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

### why isnt this a conventional danbooru/hydrus model

the name of a tag isnt unique, tags map to their own tag ids (tag "cores" as ids would be overused vocab from DB world), except, to make this work at universe-scale where i can share my tags with you without conflicting with anything pre-existing

the idea of is shamelessly being copied from the proposal here: https://www.nayuki.io/page/designing-better-file-organization-around-tags-not-hierarchies#complex-indirect-tags

i dont follow that proposal to the letter (storage pools do not apply to me at the moment), but some ideas from it are pretty good to follow

we use hash(random data) as the id, which enables Universal Ids But Theyre Not UUIDs You Cant Just Collide The Tags Lmao (since if you try to change the core_data by even 1 byte, crypto hash gets avalanche effect'd). this enables us to have 'tree (english)', while also having 'Árvore (portuguese)' map to the same id

ofc someone can create a different tag core for the idea of a tree, but thats out of scope. its better than hydrus's PTR because of the fact you can add different human representations to the same tag core, breaking your depedency on english, while also enabling metadata to be added to a tag core, so if i wanted to add the wikipedia link for a tree, i can do that

### some implementation details

now that i have a bit of spec like the db, what happens for implementation?

i want to have something that isnt monolithic, there is no http api of the sorts to manage the database, you just open it, and sqlite will take care of concurrent writers (file based locking)

you just use libboorufs (name tbd) and itll provide you the high level api such as "execute this query"

there needs to be at least the watcher daemon, but what about secondary functionality? say, i want a program to ensure the hashes are fine for the files, but do it in an ultra slow way, generating reports or even calling notify-send when it finds a discrepancy in hashes

that is a feature way out of scope for the "watcher daemon that only checks up for new renames in the entire filesystem. also thw watcher requires root", adding more things to that piece of code leads to opening my surface area for catastrophic failure. the system should handle all of those processes reading and writing to the database file

#### the db is an IPC platform for all tools

this does infer that the database needs to have more than the tagging data

but a way to become an IPC format between all boorufs utilities

maybe a janitor process is ensuring all files exist and you want to see the progress bar and plan accordingly, while also ensuring there isn't two of them having to clash with each other's work

ipc and job system

#### one singular tool that does db administration

one tool will have to be database management though

the database migrations will have to go to A Tool Somewhere

maybe boorufs-manage

create db, run some statistics, show migration warnings, etc

the watcher stays as is, just a watcher for file renames

## how

WIP.

## install

WIP.

## roadmap

WIP.
