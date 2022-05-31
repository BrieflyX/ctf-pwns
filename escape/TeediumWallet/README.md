# Teedium Wallet - DefCON CTF 2022 Quals

A trusted application running in AArch64 OPTEE

Unfortunately, I didn't solve the challenge during the competition, but with some efforts, I left some stuffs to help reversing and building exploit.

## Building signature for static library

According to [this](https://optee.readthedocs.io/en/latest/building/gits/optee_os.html), I first install arm [toolchains](https://optee.readthedocs.io/en/latest/building/toolchains.html#toolchains) from https://developer.arm.com/-/media/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf.tar.xz. After clone optee_os [repo](https://github.com/OP-TEE/optee_os), we also need some prerequisites:

``` bash
sudo apt-get install -y build-essential python3 python3-pyelftools python3-cryptography device-tree-compiler
```

Then we could build the os binaries

``` bash
make \
    CFG_TEE_BENCHMARK=n \
    CFG_TEE_CORE_LOG_LEVEL=3 \
    CROSS_COMPILE=arm-none-linux-gnueabihf- \
    CROSS_COMPILE_core=arm-none-linux-gnueabihf- \
    CROSS_COMPILE_ta_arm32=arm-none-linux-gnueabihf- \
    CROSS_COMPILE_ta_arm64=aarch64-linux-gnu- \
    DEBUG=1 \
    O=out/arm \
    PLATFORM=vexpress-qemu_virt
```

Then we could find several static libraries on `./out/arm/ta_arm32-lib`, there are `libdl.a`, `libmbedtls.a`, `libutee.a` and `libutils.a`.
By using FLAIR sdk we could generate signagure file (`.sig`) and load into ida.

For reversing the main logic `7dc089d2-883b-4f7b-8154-ea1db9f1e7c3.ta`, we could simply convert it into an elf.

``` bash
dd if=7dc089d2-883b-4f7b-8154-ea1db9f1e7c3.ta of=7dc089d2-883b-4f7b-8154-ea1db9f1e7c3.elf bs=328 skip=1
```

After loading signature files, the effect is quite acceptable.

## Interaction with TA

To build exploit and interact with TA, I refer to some [examples](https://github.com/linaro-swg/optee_examples/).
To build a simple CA, we need a header file defining API (`tee_client_api.h`), and libraries copied from rootfs.
And we could simply reuse `main.c` in `optee_examples/helloword_world/host`.

## Reference

- Official repo (with source code): https://ptr-yudai.hatenablog.com/entry/2020/06/01/102049#Pwn-340pts-Trusted-Node

- [optee_os](https://github.com/OP-TEE/optee_os)
- [Build opteeos](https://optee.readthedocs.io/en/latest/building/gits/optee_os.html)
- [Arm GNU toolchains](https://developer.arm.com/open-source/gnu-toolchain/gnu-a/downloads)
- [Debugging TA](https://github.com/ForgeRock/optee-build/blob/master/docs/debug.md)
- [OPTEE Example App](https://github.com/linaro-swg/optee_examples/)

Some writeups:

- https://github.com/perfectblue/ctf-writeups/tree/master/2022/realworld-ctf-2022/untrustZone
- https://github.com/perfectblue/ctf-writeups/tree/master/2022/realworld-ctf-2022/trust_or_not