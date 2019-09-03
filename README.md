SQUASHFS Dumper
===============

A tool for viewing or extracting files from a SQUASHFS image.

About SQUASHFS
==============

SQUASHFS is mostly used for the rootfile system in home routers, like tp-link, or openwrt.


Usage
=====

List files:

    python3 dumpsqsh.py  roootfs.squash

Extract files:

    python3 dumpsqsh.py -d dst roootfs.squash

Dump filesystem tables:

    python3 dumpsqsh.py --dump roootfs.squash


Installation
============

No special dependencies need to be installed.


Similar linux tools
===========

Extracting:

    sasquatch -f  -li -c xz -d dst rootfs.squash  

Listing:

    sasquatch -ll rootfs.squash

Problem, is that `sasquatch` fails to work properly on quite a few images.


TODO
====

 * add option to view only specific files.


Author
======

Willem Hengeveld <itsme@xs4all.nl>


