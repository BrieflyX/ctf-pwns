# HXP 2018 - Green Computing I

The challenge target is to become root, but there is no vulnerability or third-party driver in kernel.

However, we could load a custom DSDT table when booting. Thus we could craft a malicious dsdt table that writes physical memory to modify kernel since kaslr is off.

Use acpica tools to dump original dsdt table, and compile it after modifying.

I choose to overwrite `sys_arch_prctl` epilogue to execute privilege escalation code, then return as normal. Since `busybox` would call `arch_prctl`, we would get root shell after booting.

## Reference

[ACPICA](https://acpica.org/)
[Implementing and Detecting an ACPI BIOS Rootkit](https://www.blackhat.com/presentations/bh-europe-06/bh-eu-06-Heasman.pdf)
[Applied anti-forensics: rootkits and kernel vulnerabilities](http://2012.zeronights.org/includes/docs/Oleksiuk.pdf)
[Upgrading ACPI tables via initrd](https://www.kernel.org/doc/Documentation/acpi/initrd_table_override.txt)