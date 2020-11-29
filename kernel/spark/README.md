# Spark - HITCON CTF 2020

A shortest path algorithm implemented in kernel.

## Vulnerabilities

1. When linking two nodes, it would push 2 edges into their link lists respectively. Thus once we release one node and free its chunk, there is a dangling pointer residing in the other node's link list.
2. In function `spark_graph_query`, when updating the distance to each node, it lacks check of index getting from node structure (offset is 0x70). If we could forge a node with a large index, then we could realize out-of-bound write.

## Exploitation

Note that by simply triggering UAF, we could leak addresses of node and stack by reading dmesg.

By utilizing typical `setxattr + userfaultfd` technique, we can easily control the node structure after releasing it. We choose to overwrite the link list of edges and make it point to our forged node structure in userspace. Then we trigger `finalize` on the other remaining node, the pointer of forged structure would be put into a connected node array, which is used in query function to find corresponding node.

Another trick is cheating query function to start from our forged node.
Imaging there are two subgraphs. One contains `a`, `b`, `c` with index 0, 1, 2; the other contains `d`, `e`, `f`, also with index 0, 1, 2. When we query distance between `a` and `e` (belonging to 2 separated graphs), the index passed into `spark_graph_query` is 0 and 1. Therefore, we actually query distance between `a` and `b`.
In the same way, I use another graph which contains index same as my forged node to finish this trick.

In this case, `spark_graph_query` would iterate my forged link list, extract the index we controlled.
We make the graph includes at least 13 nodes thus the distance array would use `kmalloc-128` to allocate chunk, which will return the address that we leak previously.
Now we have the distance array address and stack address, we choose to overwrite return address stored on the stack. Since there is no SMAP / SMEP, getting root is trivial via executing shellcode located in userspace.