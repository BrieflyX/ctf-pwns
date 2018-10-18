# Faststorage - Teaser Dragon Sector CTF 2018

Use hashmap and bitmap to search for `name`

## Vulnerability

The `key` is calculated via `abs(x)%62`, then it would be used as index of `hashmap` and `bitmap`. However, `abs(0x80000000)%2 = 0x80000000%2 = -2`, that causes collision of `-2` element of `hashmap` and `60,61` elements of `bitmap`.

## Exploitation

Put a heap pointer at `-2` element of `hashmap`, then use `bitmap` to leak heap address. Then shift heap pointer to modify `top chunk` size leaking libc address.
