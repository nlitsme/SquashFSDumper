SQUASHFS Dumper
===============

A tool for viewing or extracting files from a SQUASHFS image.

Only v4.0 is supported.

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

To support all compression modes, you may need to install some additional modules:

    pip install python-lzo
    pip install zstd
    pip install lz4


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
 * support v2 and v3 formats

Author
======

Willem Hengeveld <itsme@xs4all.nl>


