# Neighbor C - TWCTF 4th 2018

Simple format string bug, but it prints to `stderr`. We could use the stderr structure pointer on the stack to do a partial overwrite. Then modify `fileno` in `stderr` thus get leak in stdout.