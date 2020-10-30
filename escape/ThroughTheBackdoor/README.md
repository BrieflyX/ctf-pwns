# Through the Backdoor - Hack.lu 2020

The description of this challenge is as following:

```
Pwnhub is hoarding a bunch of valuable exploits, we could make good use of. The CEO is pretty careless and let his laptop unattended. One of our agents installed a backdoor on the device, but all important data was on an external drive. Unfortunately no one knows how this backdoor works and the developer is no longer around. But I remember he was always talking about some UEFI... The CEO is now back on his laptop and hacking on more exploits, remote service at flu.xxx port 2030. Go fast and get those exploits for us and we will reward you generously.
```

It seems there is a backdoor in DXE program and we need to misuse it for root shell.
I did not look into this challenge.

External solution script: https://gist.github.com/disconnect3d/3c3f94a4da1b83aa7843382795576cf9. A local copy is [here](./hacklu2020_backdoor_pwn_solver.py).