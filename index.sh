#!/bin/bash

sed -i "" -e '/## Index/,$d' ./README.md
echo "## Index" >> ./README.md
echo "" >> ./README.md

mds=$(find . -name "README.md" | xargs ls -1t)

for md in $mds; do
    head -n1 $md | grep -q "-" && echo "- ["$(head -n1 $md | sed 's/# //g')"]("$(echo $md | sed 's/\/README.md//g')")" >> ./README.md
done
