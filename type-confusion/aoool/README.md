# Defcon CTF 2019 Finals - Aoool
# Pwn

This is quite a tough challenge in defcon finals. The binary implements a web server that has `GET`, `UC` and `UF` method.
When parsing configuration files, it utilizes `flex` and `bison` to generate parsing code, which is hard to reverse in binary level. We recovered DFA in `yylex` function but failed to extract PDA in `yyparse` function.
Facing several tokens, we guessed the configuration file format and found `mode osl` could make program parse another format and covert it into jit code.
In jit code, there are `string` and `int` type, thus causes a type confusion bug.