# Off-by-one vulnerability

Mostly, (null byte) off-by-one on pointer can cause overlapped chunk directly. When the byte is on `sz` of a chunk, it may come to *shrink the free chunk* or *house of einherjar*.