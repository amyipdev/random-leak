# RandomLeak Linux Kernel Module

`random-leak` is a Linux kernel module with one simple job:
leaking random parts of your kernel's memory, for your
convenience. It provides:

- 🖥️ Random bytes drawn from the kernel
- 🦺 Sanitized outputs (no `NUL` bytes)
- ⚖️ Easy configuration of output size

Accidentally revealing sensitive kernel information is as easy
as 1-2-`cat`!

## Installation

We currently only support manually loading the module.
If you'd like installation/`dkms` support, or package-bundled
versions, file an [Issue](https://github.com/amyipdev/random-leak/issues/new).

Commands starting with `$` do not need to be run as a superuser/`root`.
Commands starting with `#` do; if you are not a superuser, you may be able
to use `sudo` or `doas` to temporarily get superuser privileges.
You should not paste/type the `$` or `#` in commands.

### Dependencies

You will need to have Linux kernel headers installed. This is
often a package like `kernel-devel` or `linux-headers-KERNELVERSION`.
Consult your Linux distributor for more information; if you need
assistance, you can file an [Issue](https://github.com/amyipdev/random-leak/issues/new).

You must also have:
- A GCC-compatible C compiler (`gcc`)
- GNU make (`make`)
- Git (`git`)
- Other Linux kernel development dependencies

> Other Make variants may work, but they have not been tested.
>
> If the variant is known to work with [Kbuild](https://docs.kernel.org/kbuild/index.html),
> then it should work fine for RandomLeak.

> The current version of the Linux kernel may have different additional
> dependencies for building kernel modules. Your distribution may have a group
> package for installing Linux kernel build dependencies, or you may have
> to resolve these through trial and error.

### Download

Clone the source repository:
```
$ git clone https://github.com/amyipdev/random-leak.git
```

### Build

Enter and build the module:
```
$ cd random-leak
$ make
```

### Load

> [!IMPORTANT]
> You **cannot have Secure Boot** enabled when loading the module, or have
> any other Linux anti-tampering measures deployed. If you have Secure
> Boot enabled, you will need to shut down, enter BIOS, and disable it;
> **do not do this if you dualboot Windows with BootLocker**, which must
> be disabled first to avoid *losing all of your data*. Once Secure Boot
> is disabled, you can load the module.

> [!NOTE]
> If you cannot disable Secure Boot or are not willing to, you may want to
> look into custom signing the RandomLeak module. See guides for
> [RHEL-deriatives](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/signing-a-kernel-and-modules-for-secure-boot_managing-monitoring-and-updating-the-kernel),
> (such as Fedora, CentOS, RHEL, Rocky, Oracle Linux, and Alma), as well as for
> [Debian-deriatives](https://ubuntu.com/blog/how-to-sign-things-for-secure-boot)
> (such as Debian, Ubuntu, Linux Mint, PopOS, Proxmox VE, and many more).

Load the module into the kernel:

```
# insmod src/random-leak.ko
```

### Unload

> [!IMPORTANT]
> If RandomLeak has crashed (response of "Killed" in a terminal, or your
> terminal/app closed), **DO NOT UNLOAD THE MODULE**. Doing so will freeze
> your terminal, brick the RandomLeak instance, and force you to hard-reboot.
> If you want to cleanly remove the module after a failure, you must reboot
> without running this command.

To remove the module from the kernel:

```
# rmmod random_leak
```

## Usage

RandomLeak exposes the `/proc/random-leak` interface for retrieving random
kernel bytes and setting the size to retrieve.

You MUST be `root` (user, not group) to use the interface. Use `sudo` or `doas`
if you don't have access to the `root` user.

To set the number of bytes to leak, write a null-terminated string to the
interface containing the number (no newlines); for instance, if you want to generate
4 KiB of random data, you can send the following from the terminal:

```
# echo -n "4096" > /proc/random-leak
```

To generate random bytes, simply read from the interface. If you're working in a
programming language, you're going to want to read as *bytes* instead of *characters*;
for instance, in Python, you'd want to pass `"rb"` to `open()` instead of `"r"`.

You can test-read from the interface from the terminal:

```
# cat /proc/random-leak
```

> [!NOTE]
> No other operations on the `/proc/random-leak` interface are supported at this time.
> If you're a developer, make sure to always read with offset=0; reading from a higher
> position will cause RandomLeak not to return any bytes (its means of communicating EOF).

## Algorithm

The actual source code is all centralized in
[src/random-leak.c](https://github.com/amyipdev/random-leak/blob/main/src/random-leak.c).

The default number of bytes to generate is 16; the returned amount will always be
one greater than the number of bytes generated to null-terminate the string.
The "random determiner" is also set to 1<<18 (262144).

On initialization, a `procfs` interface is launched at `/proc/random-leak` with
`600` permissions. A `drbg-nopr-sha256` RNG is also initialized. Because the Linux
kernel [removed `kallsyms` symbols from exports](https://lwn.net/Articles/813350/),
a `kprobe` is used to fetch `kallsyms_on_each_symbol`.

On write, the first 10 bytes of the user buffer are copied into a new buffer, which
is parsed via `kstrtou32` with safety. If this fails, the fail code is returned.
Otherwise, the number of bytes to return is updated.

To avoid later conflicts with the bytes-to-fetch count, the value is cached on read.
After ensuring that the user buffer is ready for writing, a new buffer is allocated.
Writes will happen into this buffer, as writing directly into the user buffer is
more difficult due to paging restrictions. A function is constructed which takes this
new buffer, the cached bytes value, and the remaining number of bytes to fetch as
inputs through a casted pointer to a stack-allocated structure.

This function is now called through the `kprobe`'d `kallsyms_on_each_symbol`. As
long as there are more bytes to fetch, kallsyms_on_each_symbol will be continuously
called. If after the execution of an iteration the operation is completed,
returning `1` is used to short-circuit `kallsyms_on_each_symbol` and return early.

On each iteration, the RNG is called to generate 4 bytes. To create a better
distribution of where our data is pulled from, this value (endian-agonstic) is taken modulo
(8 * random determiner / bytes to generate). Because the expected value
of bytes to pull from any given symbol is 8 (mod 16), this creates a fair distribution
of symbol selection. If the value post-transformation equals 0, then this symbol
will move onto the next stage; otherwise, execution continues onto the next symbol.

If a symbol is selected for generation, one byte is pulled from the RNG. We know that,
on almost all platforms, pulling memory from the current page is always safe, so we
calculate how much free space is remaining in the page as
`PAGE_SIZE` - (symbol's address mod `PAGE_SIZE`). The number of bytes we can
safely read is equal to the minimum of the remaining bytes and the space remaining
in the page; we take the minimum of those, as well as the one byte generated, to
determine how many bytes to retrieve. This value is taken modulo 16, as we don't want
to pull too many bytes from the same symbol; this gives the previously mentioned
expected value per symbol of 8.

Another 4 bytes are generated from the RNG. These are interpreted endian-agnostically,
and taken modulo (remaining bytes in page - bytes to draw). This is added onto the
address of the current symbol, and the bytes are manually copied into the buffer.

> [!NOTE]
> There is potential to speed this up using kernel memory functions or through
> larger word sizes. It probably isn't necessary, as the maximum number of bytes
> that get pulled at any time is 16; however, if you'd like to work on this performance
> aspect, see the Contributing section below.

Once all the bytes have been gathered, the new buffer is copied to the user buffer,
and the new buffer is freed; the data is then returned to the user.

## Contributing

To report bugs, file an [Issue](https://github.com/amyipdev/random-leak/issues/new).

If you'd like to contribute, file a [Pull Request](https://github.com/amyipdev/random-leak/pulls).
We ask that you follow the style guidelines that are used by the
[Linux kernel itself](https://www.kernel.org/doc/html/latest/process/submitting-patches.html),
including signing-off your patches and PRs.

Please note that any changes you make or submit are subject to the
GNU General Public License, version 2 only. For more information, see the
Licensing section.

## Why?

To be clear, this module is by no means meant to be practically
used by, well, anyone. It is quite silly, and should **NEVER** be used on a
production system due to the pretty inherent security vulnerabilities it presents.

What this project did allow me to do, though, was re-orient myself with Linux
kernel development. I've been out of the scene for some time, and really needed
a refresher on how this stuff is done. I would've worked on a more practical project,
but didn't have anything immediate at the time; I also just wanted something smaller
to ease me back in.

## Licensing

Copyright (c) 2023 Amy Parker <[amy@amyip.net](mailto:amy@amyip.net)>

This project is licensed under the GNU General Public License,
version 2. A copy of this license can be found in the
[`LICENSE`](https://github.com/amyipdev/random-leak/blob/main/LICENSE) file,
or for your convenience at https://www.gnu.org/licenses/gpl-2.0.html.

This project links with the Linux kernel, which has components that are
licensed under GPL-2.0-only. You may not use this module with any components
that are not GPL compatible. You can find information on the legal requirements
for derivative and linked works of RandomLeak at the
[Linux kernel docs](https://docs.kernel.org/process/license-rules.html).
