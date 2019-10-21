# Defcon CTF 2019 Finals - Babi

A rust challenge implements a web server to unserialize php-like data manually. When handling `ref` type, it uses shallow copy, which causes a double free when deconstructing vector.