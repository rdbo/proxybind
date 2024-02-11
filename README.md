# proxybind
A failproof alternative to proxychains

## What's wrong with proxychains?
The problem with proxychains is that it uses `LD_PRELOAD` and "hooks" the libc functions related to socket functionality in order to intercept them and put a proxies in the middle.

Why is it bad? Well, it only works for programs dynamically linked against a libc, so statically linked programs would be safe, and also any program that doesn't use the libc's functions for socket programming.

Don't take my word for it; this is from the [`proxychains-ng`](https://github.com/rofl0r/proxychains-ng) readme:
```
  The way it works is basically a HACK; so it is possible that it doesn't
  work with your program, especially when it's a script, or starts
  numerous processes like background daemons or uses dlopen() to load
  "modules" (bug in glibc dynlinker).
  It should work with simple compiled (C/C++) dynamically linked programs
  though.
```

## How does proxybind work?
It works by intercepting system calls related to socket functionality, and modifying their parameters to make sure that the wanted traffic goes through the proxies.

Because it intercepts system calls directly, it is practically impossible for a program to not work with proxybind, because no matter what library/implementation they use for socket programming,
they still have to tell the operating system to create a socket, send data, etc, which requires going through the system calls.

This means that proxybind should work with basically every program.

## License
This project is licensed under the `AGPL-3.0` license.

Read the `LICENSE` file in the root directory of this project for more information.

## Status
Currently, proxybind is a work in progress.
