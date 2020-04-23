# Ipppc - Plaid CTF 2020

This challenge was solved by my teammate.
The basic principle is leveraging fd passes by parent process. Since it is `char` type, when parent process fd exceeds 256, it may pass fd of `/workdir` to child.