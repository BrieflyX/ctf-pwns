# Production - Teaser Dragon Sector CTF 2018

Look at this production-level lyrics reader.

## Vulnerability

`assert` macros don't work in release version, thus a `close` in the `assert` macro won't be compiled.

## Exploitation

Since the program limits process `NOFILE` to 32, we could reach the max file descriptor limit to make symbolic link check fail. In this case, we could open `flag` file. At last, we could read one `EOF`ed file to leak uncleared content buffer in `read_lyrics` for bypassing content check.
