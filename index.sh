#!/bin/bash

mds=$(find . -name "README.md" | xargs ls -1t)

for md in $mds; do
    head -n1 $md | grep -q "-" && echo "- ["$(head -n1 $md | sed 's/# //g')"]("$md")" 
done
