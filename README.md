# idontgiveashell

## Description

A colleague of mine wanted to enjoy the powerful features of my CPU but
I don't trust him enough to give a shell on my computer. This program
expects to receive a raw shellcode or a shared library, and executes it
inside a seccomp-bpf sandbox.


## Technical details

The following syscalls are allowed by seccomp-bpf:
* `rt_sigreturn`,
* `exit`,
* `exit_group`,
* `read`,
* `write`,
* `mmap`,
* `mprotect`,
* `getcwd`.

memdlopen (https://github.com/m1m1x/memdlopen) is used to load a dynamic
library from memory. Despite being a proof of concept, the idea is
awesome and it works great. (The code has been heavily rewritten to be a
little bit more readable).

CPU time and memory are limited thanks to alarm and rlimits.


## Tests

Tested on Ubuntu 14.04.2 LTS (ld-2.19.so).
