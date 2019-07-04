Test for implemented ioctls/types in x/sys/unix
===============================================

This repository contains some tests for linux tun interface to see if everything in https://go-review.googlesource.com/c/sys/+/185057 works.

Can also be used as basis for how to use the tun interface in go.

Test must be run as `root` or with `CAP_NET_ADMIN`.
