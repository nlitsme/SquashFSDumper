"""
`dumpsqsh` - a tool for viewing or extracting SquashFS contents

Author: (C) 2019  Willem Hengeveld <itsme@xs4all.nl>
"""
import lzma
import zlib
import struct
from binascii import b2a_hex
import datetime
import os
import os.path


# dir entry types
SQUASHFS_DIR_TYPE       = 1
SQUASHFS_REG_TYPE       = 2
SQUASHFS_SYMLINK_TYPE   = 3
SQUASHFS_BLKDEV_TYPE    = 4
SQUASHFS_CHRDEV_TYPE    = 5
SQUASHFS_FIFO_TYPE      = 6
SQUASHFS_SOCKET_TYPE    = 7
# inode types
SQUASHFS_LDIR_TYPE      = 8
SQUASHFS_LREG_TYPE      = 9
SQUASHFS_LSYMLINK_TYPE  = 10
SQUASHFS_LBLKDEV_TYPE   = 11
SQUASHFS_LCHRDEV_TYPE   = 12
SQUASHFS_LFIFO_TYPE     = 13
SQUASHFS_LSOCKET_TYPE   = 14

itypenames = [ "NUL", "DIR", "REG", "SYM", "BLK", "CHR", "FIFO", "SOCK",
            "LDIR", "LREG", "LSYM", "LBLK", "LCHR", "LFIFO", "LSOCK" ]

# filesystem flags
SQUASHFS_NOI            =  0
SQUASHFS_NOD            =  1
SQUASHFS_CHECK          =  2
SQUASHFS_NOF            =  3
SQUASHFS_NO_FRAG        =  4
SQUASHFS_ALWAYS_FRAG    =  5
SQUASHFS_DUPLICATE      =  6
SQUASHFS_EXPORT         =  7
SQUASHFS_NOX            =  8
SQUASHFS_NO_XATTR       =  9
SQUASHFS_COMP_OPT       = 10
SQUASHFS_NOID           = 11

fsflagnames = [ "NOI", "NOD", "CHECK", "NOF", "NO_FRAG", "ALWAYS_FRAG",
        "DUPLICATE", "EXPORT", "NOX", "NO_XATTR", "COMP_OPT", "NOID" ]

# xattr types
SQUASHFS_XATTR_USER      = 0
SQUASHFS_XATTR_TRUSTED   = 1
SQUASHFS_XATTR_SECURITY  = 2

xatypenames = [ "USER", "TRUSTED", "SECURITY" ]

# compression types
ZLIB_COMPRESSION      = 1
LZMA_COMPRESSION      = 2
LZO_COMPRESSION       = 3
XZ_COMPRESSION        = 4
LZ4_COMPRESSION       = 5
ZSTD_COMPRESSION      = 6

compnames = [ "ZLIB", "LZMA", "LZO", "XZ", "LZ4", "ZSTD" ]


def log(*args):
    #print("##", *args)
    pass


def timestr(t):
    return datetime.datetime.utcfromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")


class OffsetReader:
    """
    Wraps around a filehandle, shifts offset '0' in the file to the specified offset.
    """
    def __init__(self, fh, ofs):
        self.baseofs = ofs
        self.fh = fh
        self.fh.seek(ofs)

    def read(self, size):
        return self.fh.read(size)

    def seek(self, pos):
        return self.fh.seek(pos+self.baseofs)


class InodeHeader:
    MINSIZE = 16

    def __init__(self, fs, data):
        self.fs = fs
        (
            self.type,
            self.mode,
            self.uid,
            self.gid,
            self.mtime,
            self.inode_idx,
        ) = struct.unpack(fs.fmt + "4H2L", data[:self.MINSIZE])

    def size(self):
        return self.MINSIZE

    def modebits(self):
        def perms(x, specialchar, specialflag):
            return "%s%s%s" % (
                    "-r"[x>>2],
                    "-w"[(x>>1)&1],
                    ("-x"+specialchar)[(x&1) + 2*specialflag]
                )
        typechar = "d-lbcps"
        mode = self.mode
        return typechar[(self.type-1)%7] \
            + perms((mode>>6)&6, "Ss", (mode>>11)&1) \
            + perms((mode>>3)&6, "Ss", (mode>>10)&1) \
            + perms((mode>>0)&6, "Tt", (mode>>9)&1)

    def idstring(self):
        return "%5d %5d" % (self.fs.idlist[self.uid],self.fs.idlist[self.gid])

    def oneline(self):
        return "%s %s  %s" % (self.modebits(), self.idstring(), timestr(self.mtime))
    def __str__(self):
        return "[%s, %s, %04d:%04d, (%s), #%04x]" % (itypenames[self.type], self.modebits(), self.uid, self.gid, timestr(self.mtime), self.inode_idx)


class LDirectoryNode:
    """
    SQUASHFS_LDIR_TYPE          8
    """
    MINSIZE = 24

    def __init__(self, fs, data):
        (
            self.nlink,
            self.file_size,
            self.start_block,  # offset relative to directory_table_start
            self.parent_inode,
            self.i_count,
            self.offset,       # offset into dir block
            self.xattr,
        ) = struct.unpack(fs.fmt + "4L2HL", data[:self.MINSIZE])

    def size(self):
        return self.MINSIZE

    def oneline(self, name):
        return "%s %3d %s %10d  %s  %s/" % (self.hdr.modebits(), self.nlink, self.hdr.idstring(), self.file_size, timestr(self.hdr.mtime), name)

    def __str__(self):
        return "n%d, s%08x, blk%06x, parent:#%04x, cnt:%d, off:%d, xa:%d" % (
            self.nlink, self.file_size, self.start_block,
            self.parent_inode, self.i_count, self.offset, self.xattr)


class LRegularNode:
    """
    SQUASHFS_LREG_TYPE          9

    the data in a file is stored as follows:

    if startblk:
        read complete blocks starting at 'startblk'
    if fragment:
        read remaining from 'offset' in 'fragment'
    """
    MINSIZE = 40

    def __init__(self, fs, data):
        (
            self.start_block, # offset to first block
            self.file_size,
            self.sparse,
            self.nlink,
            self.fragment,    # idx into fragment table
            self.offset,      # offset into fragment
            self.xattr,
        ) = struct.unpack(fs.fmt + "3Q4L", data[:self.MINSIZE])

        # nr of complete blocks
        nblocks = self.file_size // fs.block_size
        self.block_size_list = struct.unpack(fs.fmt + "%dL" % nblocks, data[self.MINSIZE:self.MINSIZE+4*nblocks])

    def size(self):
        return self.MINSIZE + 4*len(self.block_size_list)

    def oneline(self, name):
        return "%s %3d %s %10d  %s  %s" % (self.hdr.modebits(), self.nlink, self.hdr.idstring(), self.file_size, timestr(self.hdr.mtime), name)

    def __str__(self):
        return "n%d, s%08x, blk%06x, sprs:%d, frag:%d, off:%d, xa:%d {%s}" % (
            self.nlink, self.file_size, self.start_block,
            self.sparse, self.fragment, self.offset, self.xattr,
            ",".join("%06x" % _ for _ in self.block_size_list))


class LDeviceNode:
    """
    SQUASHFS_LBLKDEV_TYPE      11
    SQUASHFS_LCHRDEV_TYPE      12
    """
    MINSIZE = 12

    def __init__(self, fs, data):
        (
            self.nlink,
            self.rdev,
            self.xattr,
        ) = struct.unpack(fs.fmt + "3L", data[:self.MINSIZE])

    def size(self):
        return self.MINSIZE

    def oneline(self, name):
        return "%s %3d %s    %3d,%3d  %s  %s" % (self.hdr.modebits(), self.nlink, self.hdr.idstring(), self.rdev>>8, self.rdev&0xFF, timestr(self.hdr.mtime), name)

    def __str__(self):
        return "n%d r%04x, xa:%d" % (self.nlink, self.rdev, self.xattr)


class LIpcNode:
    """
    SQUASHFS_LFIFO_TYPE        13
    SQUASHFS_LSOCKET_TYPE      14
    """
    MINSIZE = 8

    def __init__(self, fs, data):
        (
            self.nlink,
            self.xattr,
        ) = struct.unpack(fs.fmt + "2L", data[:self.MINSIZE])

    def size(self):
        return self.MINSIZE

    def oneline(self, name):
        return "%s %3d %s             %s  %s" % (self.hdr.modebits(), self.nlink, self.hdr.idstring(), timestr(self.hdr.mtime), name)

    def __str__(self):
        return "n%d xa:%d" % (self.nlink, self.xattr)


class DirectoryNode:
    """
    SQUASHFS_DIR_TYPE          1
    """
    MINSIZE = 16

    def __init__(self, fs, data):
        (
            self.start_block,  # offset relative to directory_table_start
            self.nlink,
            self.file_size,
            self.offset,       # offset into dir block
            self.parent_inode,
        ) = struct.unpack(fs.fmt + "2L2HL", data[:self.MINSIZE])

    def size(self):
        return self.MINSIZE

    def oneline(self, name):
        return "%s %3d %s %10d  %s  %s/" % (self.hdr.modebits(), self.nlink, self.hdr.idstring(), self.file_size, timestr(self.hdr.mtime), name)

    def __str__(self):
        return "blk%06x, n%d, s%08x, off:%08x, parent:#%04x" % (self.start_block, self.nlink, self.file_size, self.offset, self.parent_inode)


class RegularNode:
    """
    SQUASHFS_REG_TYPE          2

    the data in a file is stored as follows:

    if startblk:
        read complete blocks starting at 'startblk'
    if fragment:
        read remaining from 'offset' in 'fragment'
    """
    MINSIZE = 16

    def __init__(self, fs, data):
        (
            self.start_block, # offset to first block
            self.fragment,    # idx into fragment table
            self.offset,      # offset into fragment
            self.file_size,
        ) = struct.unpack(fs.fmt + "4L", data[:self.MINSIZE])

        # nr of complete blocks
        nblocks = self.file_size // fs.block_size
        self.block_size_list = struct.unpack(fs.fmt + "%dL" % nblocks, data[self.MINSIZE:self.MINSIZE+4*nblocks])

    def size(self):
        return self.MINSIZE + 4*len(self.block_size_list)

    def oneline(self, name):
        return "%s %3d %s %10d  %s  %s" % (self.hdr.modebits(), 1, self.hdr.idstring(), self.file_size, timestr(self.hdr.mtime), name)

    def __str__(self):
        return "s%08x, blk%06x, off:%d {%s}" % (
            self.file_size, self.start_block, self.offset,
            ",".join("%06x" % _ for _ in self.block_size_list))



class SymlinkNode:
    """
    SQUASHFS_LSYMLINK_TYPE     10
    SQUASHFS_SYMLINK_TYPE       3
    """
    MINSIZE = 8

    def __init__(self, fs, data):
        (
            self.nlink,
            symlink_size,
        ) = struct.unpack(fs.fmt + "2L", data[:self.MINSIZE])
        self.symlink = data[self.MINSIZE:self.MINSIZE+symlink_size].decode('utf-8')

        # TODO: which is the zero DWORD after the symlink string ?

    def size(self):
        return self.MINSIZE+len(self.symlink)

    def oneline(self, name):
        return "%s %3d %s             %s  %s -> %s" % (self.hdr.modebits(), self.nlink, self.hdr.idstring(), timestr(self.hdr.mtime), name, self.symlink)

    def __str__(self):
        return "n%d -> %s" % (self.nlink, self.symlink)


class DeviceNode:
    """
    SQUASHFS_LBLKDEV_TYPE      11
    SQUASHFS_LCHRDEV_TYPE      12
    SQUASHFS_BLKDEV_TYPE        4
    SQUASHFS_CHRDEV_TYPE        5
    """
    MINSIZE = 8

    def __init__(self, fs, data):
        (
            self.nlink,
            self.rdev,
        ) = struct.unpack(fs.fmt + "2L", data[:self.MINSIZE])

    def size(self):
        return self.MINSIZE

    def oneline(self, name):
        return "%s %3d %s    %3d,%3d  %s  %s" % (self.hdr.modebits(), self.nlink, self.hdr.idstring(), self.rdev>>8, self.rdev&0xFF, timestr(self.hdr.mtime), name)

    def __str__(self):
        return "n%d r%04x" % (self.nlink, self.rdev)


class IpcNode:
    """
    SQUASHFS_LFIFO_TYPE        13
    SQUASHFS_LSOCKET_TYPE      14
    SQUASHFS_FIFO_TYPE          6
    SQUASHFS_SOCKET_TYPE        7
    """
    MINSIZE = 4

    def __init__(self, fs, data):
        (
            self.nlink,
        ) = struct.unpack(fs.fmt + "L", data[:self.MINSIZE])

    def size(self):
        return self.MINSIZE

    def oneline(self, name):
        return "%s %3d %s             %s  %s" % (self.hdr.modebits(), self.nlink, self.hdr.idstring(), timestr(self.hdr.mtime), name)

    def __str__(self):
        return "n%d" % (self.nlink)


class DirHeader:
    """
    Start of a list of RelativeDirEntry's in the directory-table.
    """
    MINSIZE = 12

    def __init__(self, fs, data):
        (
            self.count,             # note: one less than nr of entries.
            self.inode_block,
            self.index_base,
        ) = struct.unpack(fs.fmt + "3L", data[:self.MINSIZE])

    def size(self):
        return self.MINSIZE

    def __str__(self):
        return "n=%d, i:%08x, #:%04x" % (self.count, self.inode_block, self.index_base)


class RelativeDirEntry:
    """
    the file_size of a dir entry is always 3 bytes larger than the actual size
    of the combined dir_headers + dir_entries

    This is because the linux driver uses the offset into the node as the 'current' entry,
    when doing 'readdir',  entries 0 and 1  are translated to "." and "..",  while 2
    is not used, and 3 and larger map to direntries.
    """
    MINSIZE = 8

    def __init__(self, fs, data):
        (
            self.inode_offset,    # offset into the block specified in the DirHeader
            self.index_delta,     # (signed int) added to the inode_number in the DirHeader
            self.type,            # 1 = dir, 2 = reg, 3 = sym, 4 = blk, 5 = chr, 6 = fifo, 7 = sock
            namelen,         # name length
        ) = struct.unpack(fs.fmt + "HhHH", data[:self.MINSIZE])
        self.name = data[self.MINSIZE : self.MINSIZE+namelen+1].decode('utf-8')

    def size(self):
        return self.MINSIZE + len(self.name)

    def __str__(self):
        return "i+%04x, #+%04x, %s - %s" % (self.inode_offset, self.index_delta, itypenames[self.type], self.name)


class DirEntry:
    """
    Resolved DirEntry
    """
    def __init__(self, inodenum, inodeidx, type, name):
        self.inode_number = inodenum
        self.inode_index = inodeidx
        self.type = type
        self.name = name

    def oneline(self):
        types = "?d-lbcps"
        return "%08x:#%03d [%s] %s" % (self.inode_number, self.inode_index, types[self.type], self.name)

    def __str__(self):
        return "i:%08x, #%04x  %s - %s" % (self.inode_number, self.inode_index, itypenames[self.type], self.name)


class XAttr:
    """
    An Extended Attribute.
    """
    def __init__(self, fs, data):
        o = 0
        (
            self.type,
            namelen,
        ) = struct.unpack(fs.fmt + "HH", data[:4])
        o += 4

        self.name = data[o:o+namelen]
        o += namelen

        vallen, = struct.unpack(fs.fmt + "L", data[o:o+4])
        o += 4

        self.value = data[o:o+vallen]
        o += vallen

        self.size = o

    def typestr(self):
        if 0 <= self.type < len(xatypenames):
            return xatypenames[self.type]
        return "unknown_%d" % self.type

    def __str__(self):
        return "%s: %s=%s" % (self.typestr(), self.name, self.value)


class SquashFs:
    """
    Loads a squashfs filesystem, provides functions for reading, and saving all files.
    """
    def __init__(self, fh):
        warns = 0
        self.fh = fh

        self.blockcache = dict()
        self.fragments = None
        self.inodemap = None
        self.idlist = None
        self.xalist = None


        self.fh.seek(0)
        hdrdata = self.fh.read(0x60)
        if not hdrdata:
            raise Exception("no data")
        magic = hdrdata[:4]
        if magic == b'sqsh':
            self.fmt = '>'
        elif magic == b'hsqs':
            self.fmt = '<'
        else:
            raise Exception("not a squashfs")

        log("SQUASH: %s" % b2a_hex(hdrdata))

        (
        self.nr_inodes,              # nr of inodes in inode_table
        self.mkfs_time,
        self.block_size,
        self.nr_fragments,           # nr of items in fragment_table
        self.compression,            # 1 = ZLIB, 2 = LZMA, 3 = LZO, 4 = XZ, 5 = LZ4, 6 = ZSTD,
        self.block_log,              # blocksize == 1<<block_log
        self.flags,                  # file system flags
        self.nr_ids,                 # nr of uid/gid's in id_table
        self.s_major,
        self.s_minor,
        self.root_inode,
        self.bytes_used,
        self.id_table_start,         # --> uint64:offset --> uint16:size + data  -->  *uint32  - uid/gid translation
        self.xattr_id_table_start,   # --> uint64,uint32  --> uint16:size + data   : [ squashfs_xattr_entry + squashfs_xattr_val ]
        self.inode_table_start,      # --> uint16:size + data  -> [ *_inde ... ]   : [ inode_hdr ... ]
        self.directory_table_start,  # --> uint16:size + data  -> [ *_inde ... ]   : [ squashfs_dir_header + [ squashfs_dir_entry ] ]
        self.fragment_table_start,   # --> uint64:offset -->  [ uint64:blkofs, uint64:size ]
        self.lookup_table_start,     # --> uint64:offset -->  [ uint64:blk:ofs ]   maps index to blk:ofs
        ) = struct.unpack(self.fmt + "4L6H8Q", hdrdata[4:])

        if 1<<self.block_log != self.block_size:
            print("WARNING: blocksize: log(%x) != %d" % (self.block_size, self.block_log))
            warns += 1
        for attr in ( "id_table_start", "xattr_id_table_start", "inode_table_start", "directory_table_start", "fragment_table_start", "lookup_table_start" ):
            val = getattr(self, attr)
            if val != 0xFFFFFFFF and val != 0xFFFFFFFFFFFFFFFF and val >= self.bytes_used:
                print("WARNING: %s > bytes used: %x > %x" % (attr, val, self.bytes_used))
                warns += 1
        if warns > 2:
            raise Exception("Too many warnings in header")

        self.opts = None
        if self.flags & (1<<SQUASHFS_COMP_OPT):
            self.opts = self.readblock(0x60)

        self.load_idlist()
        if self.xattr_id_table_start != (1<<64)-1:
            self.load_xalist()
        self.load_fragmentlist()
        self.load_lookuptable()

    def compname(self):
        """
        Returns the name of the filesystem's compression algorithm.
        """
        if 1 <= self.compression <= len(compnames):
            return compnames[self.compression-1]
        return "unknown_%d" % self.compression

    def flagstring(self):
        """
        Returns a string showing which filesystem flags are set.
        """
        l = []

        remainingbits = self.flags & ~((1<<len(fsflagnames))-1)
        if remainingbits:
            l.append("unknown_%x" % remainingbits)
        flag = self.flags
        for name in fsflagnames:
            if flag & 1:
                l.append(name)
            flag >>= 1

        return ",".join(l)

    def decompress(self, data):
        """
        Decompress a datablock.

        Not all algorithms are supported yet.
        """
        if self.compression == XZ_COMPRESSION:
            return lzma.decompress(data)
        elif self.compression == ZLIB_COMPRESSION:
            return zlib.decompress(data)
        elif self.compression == LZMA_COMPRESSION:
            return lzma.decompress(data[:5] + b'\xff'*8 + data[5:])
        raise Exception("Compression type %d not supported" % self.compression)

    def read_value(self, offset, fmt):
        """
        Reads an integer value from the specified filesystem offset.
        """
        if fmt == "Q": fmtsize = 8
        elif fmt == "L": fmtsize = 4
        elif fmt == "H": fmtsize = 2
        elif fmt == "B": fmtsize = 1
        else: raise Exception("invalid format: %s" % fmt)

        self.fh.seek(offset)
        value, = struct.unpack(self.fmt + fmt, self.fh.read(fmtsize))

        return value

    def load_idlist(self):
        """
        Read uid/gid map. The uid and gid values in inodes contain an index into
        this table.
        """
        # TODO: there can be more than one entry here!!
        idblock = self.read_value(self.id_table_start, "Q")

        data = self.readblock(idblock)
        self.idlist = struct.unpack(self.fmt + "%dL" % (len(data)//4), data)
        if len(self.idlist) != self.nr_ids:
            print("WARNING: nr ids does not match size of idlist block")

    def load_xalist(self):
        """
        Reads the eXtended Attribute list, these are referenced from dir and file inodes.
        """
        # TODO: when xaindex is larger than one block, there may be more xaindexofs entries.
        self.fh.seek(self.xattr_id_table_start)
        data = self.fh.read(24)
        (
            xatableofs,
            nr_xaentries,
            xaindexofs,
        ) = struct.unpack(self.fmt + "3Q", data)

        xadata = self.readblock(xatableofs)
        xaindexdata = self.readblock(xaindexofs)

        xaindex = [ struct.unpack_from(self.fmt + "QLL", xaindexdata, i*16) for i in range(nr_xaentries) ]

        self.xalist = []
        for i in range(nr_xaentries):
            ofs, cnt, size = xaindex[i]
            self.xalist.append(XAttr(self, xadata[ofs:ofs+size-2]))

    def load_fragmentlist(self):
        """
        Reads the fragment list, this is used to find the size of the fragment blocks,
        needed when decompressing them.
        """
        # TODO: there can be more than one entry here!!
        fraglist_ofs = self.read_value(self.fragment_table_start, "Q")

        data = self.readblock(fraglist_ofs)

        if len(data)//16 != self.nr_fragments:
            print("WARNING: frag list has %d, while header says: %d expected" % (len(data)//16, self.nr_fragments))

        self.fragments = [ struct.unpack_from(self.fmt + "QQ", data, 16*i) for i in range(len(data)//16) ]

    def load_lookuptable(self):
        """
        Read the #inum to inode_number translation table.
        """
        self.fh.seek(self.lookup_table_start)

        nr_lookuptables = (self.nr_inodes-1) // 0x400 + 1
        lookup_ofs = struct.unpack(self.fmt + "%dQ" % nr_lookuptables, self.fh.read(8 * nr_lookuptables ))

        self.inodemap = ()
        for ofs in lookup_ofs:
            data = self.readblock(ofs)

            self.inodemap += struct.unpack(self.fmt + "%dQ" % (len(data)//8), data)

        if len(self.inodemap) != self.nr_inodes:
            print("WARNING: inode list has %d, while header says: %d expected" % (len(self.inodemap), self.nr_inodes))

    def readinode(self, num):
        """
        Reads one inode, given an inode_number from the inode_table.
        """
        log("readinode %x" % num)
        blkofs = num >> 16
        nodeofs = num & 0xFFFF

        data = self.readblock(self.inode_table_start + blkofs)

        data = data[nodeofs:]
        if len(data) < InodeHeader.MINSIZE:
            data += self.readblock(self.nextblock(self.inode_table_start + blkofs))

        hdr = InodeHeader(self, data)
        log(hdr.oneline())

        types = {
            1: DirectoryNode,
            2: RegularNode,
            3: SymlinkNode,
            4: DeviceNode,
            5: DeviceNode,
            6: IpcNode,
            7: IpcNode,

            8: LDirectoryNode,
            9: LRegularNode,
           10: SymlinkNode,
           11: LDeviceNode,
           12: LDeviceNode,
           13: LIpcNode,
           14: LIpcNode,
        }
        cls = types.get(hdr.type)
        if not cls:
            raise Exception("Unsupported inode type: %d" % hdr.type)

        if len(data) < hdr.size() + cls.MINSIZE + 256:
            data += self.readblock(self.nextblock(self.inode_table_start + blkofs))
        node = cls(self, data[hdr.size():])
        node.hdr = hdr

        return node

    def readdir(self, blk, ofs, size):
        """
        Returns a list if DirEntry's, read from the directory_table.
        """
        entries = []
        data = b''
        blkofs = self.directory_table_start+blk
        while len(data) < ofs + size:
            data += self.readblock(blkofs)
            blkofs = self.nextblock(blkofs)
        data = data[ofs:ofs+size]

        log("data = %x, size=%x" % (len(data), size))

        o = 0
        while o < len(data):
            log("o=%x" % o)
            hdr = DirHeader(self, data[o:])
            log("hdr: %s" % b2a_hex(data[:hdr.size()]))
            o += hdr.size()
            for i in range(hdr.count+1):
                log("---: %s" % b2a_hex(data[o:o+256]))
                ent = RelativeDirEntry(self, data[o:])
                log("ent: %s" % b2a_hex(data[o:o+ent.size()]))
                entries.append(DirEntry((hdr.inode_block<<16) + ent.inode_offset, hdr.index_base + ent.index_delta, ent.type, ent.name))

                o += ent.size()
        if o != len(data):
            print("WARNING: dir size mismatch")

        return entries

    def readblock(self, blkofs, size = None, compressed = True):
        """
        Reads and optionally decompres one data block.

        when `size` and `compressed` are not specified, these
        are read from the first 16-bit value at `blkofs`.
        """

        log("block ofs = %x, size = %s" % (blkofs, "%x" % size if size is not None else "-"))
        self.fh.seek(blkofs)

        # note: compsize is the size including the optional header word.
        if blkofs not in self.blockcache:
            if size is None:
                size, = struct.unpack(self.fmt + "H", self.fh.read(2))
                log("read size: %x" % size)
                compsize = size + 2
                if size&0x8000:
                    compressed = False
                    size &= 0x7fff
            else:
                compsize = size

            data = self.fh.read(size)
            log("read data: %s" % b2a_hex(data))
            if compressed:
                data = self.decompress(data)
            self.blockcache[blkofs] = (data, compsize)
        else:
            data, compsize = self.blockcache.get(blkofs)
        return data

    def nextblock(self, blkofs):
        """
        Returns the block after `blkofs`.

        This is used when reading inodes or dir entries.
        """
        log("nextblk[%08x]" % blkofs)
        if blkofs not in self.blockcache:
            raise Exception("nextblock needs to know where previous block is")
        data, compsize = self.blockcache.get(blkofs)

        return blkofs + compsize

    def listfiles(self, inum, path = ''):
        """
        Recurseively list all files in the directory `inum`
        """
        inode = self.readinode(inum)
        if inode.hdr.type not in (SQUASHFS_DIR_TYPE, SQUASHFS_LDIR_TYPE):
            raise Exception("listfiles must be called with a dir node")
        files = self.readdir(inode.start_block, inode.offset, inode.file_size - 3)

        print("%s:" % path)
        for ent in files:
            log("ENT:", ent.oneline())
            inode = self.readinode(ent.inode_number)
            if inode.hdr.type not in (ent.type, ent.type + 7):
                print("WARNING: dirent(%d) / inode(%d) type mismatch" % (ent.type, inode.hdr.type))
            print(inode.oneline(ent.name))
        print()

        # recurse into subdirectories
        for ent in files:
            if ent.type == SQUASHFS_DIR_TYPE:
                self.listfiles(ent.inode_number, os.path.join(path, ent.name))

    def savefiles(self, inum, savedir, path = ''):
        """
        Recurseively save all files in the directory `inum` to `savedir`
        in the subdirectory `path`.
        """
        inode = self.readinode(inum)
        if inode.hdr.type not in (SQUASHFS_DIR_TYPE, SQUASHFS_LDIR_TYPE):
            raise Exception("savefiles must be called with a dir node")
        files = self.readdir(inode.start_block, inode.offset, inode.file_size - 3)

        for ent in files:
            log("ENT:", ent.oneline())
            inode = self.readinode(ent.inode_number)
            if inode.hdr.type not in (ent.type, ent.type + 7):
                print("WARNING: dirent(%d) / inode(%d) type mismatch" % (ent.type, inode.hdr.type))
            if inode.hdr.type in (SQUASHFS_REG_TYPE, SQUASHFS_LREG_TYPE):
                self.savefile(inode, os.path.join(savedir, path, ent.name))
            elif inode.hdr.type in (SQUASHFS_DIR_TYPE, SQUASHFS_LDIR_TYPE):
                os.makedirs(os.path.join(savedir, path, ent.name), exist_ok=True)

        # recurse into subdirectories
        for ent in files:
            if ent.type == SQUASHFS_DIR_TYPE:
                self.savefiles(ent.inode_number, savedir, os.path.join(path, ent.name))

    def savefile(self, inode, dstpath):
        """
        Save the file data for `inode` in `dstpath`.
        """
        with open(dstpath, "wb") as fh:

            if inode.start_block:
                blkofs = inode.start_block

                for blksize in inode.block_size_list:
                    compressed = True
                    if blksize & 0x01000000:
                        blksize &= 0x00FFFFFF
                        compressed = False

                    data = self.readblock(blkofs, blksize, compressed)
                    fh.write(data)
                    blkofs += blksize & 0xFFFFF

            if inode.fragment != 0xFFFFFFFF:
                fragofs, fragsize = self.fragments[inode.fragment]
                compressed = True
                if fragsize & 0x01000000:
                    fragsize &= 0x00FFFFFF
                    compressed = False

                data = self.readblock(fragofs, fragsize, compressed)
                remainingsize = inode.file_size % self.block_size
                fh.write(data[inode.offset : inode.offset + remainingsize ])

    def dumpinfo(self):
        print("superblock:")
        print("nr inodes    - %8d" % self.nr_inodes)
        print("mkfs time    - %s" % timestr(self.mkfs_time))
        print("blocksize    - %08x" % self.block_size)
        print("nr frags     - %8d" % self.nr_fragments)
        print("compression  - %s" % self.compname())
        print("blocklog     - %8d" % self.block_log)
        print("flags        - %s" % self.flagstring())
        print("nr ids       - %8d" % self.nr_ids)
        print("version      - %d.%d" % (self.s_major, self.s_minor))
        print("root node    - i:%08x" % self.root_inode)
        print("bytes used   - %08x" % self.bytes_used)
        print("id table     - %08x" % self.id_table_start)
        print("xattr table  - %08x" % self.xattr_id_table_start)
        print("inode table  - %08x" % self.inode_table_start)
        print("dir table    - %08x" % self.directory_table_start)
        print("frag table   - %08x" % self.fragment_table_start)
        print("lookup table - %08x" % self.lookup_table_start)
        print("idlist       - %s" % (self.idlist,))

        if self.opts:
            print("compopts     - %s" % b2a_hex(self.opts))
        print()

        if self.xalist:
            print("xattrs:")
            for i, xa in enumerate(self.xalist):
                print("%d: %s" % (i, xa))
            print()

        print("fragments:")
        for i, (off, size) in enumerate(self.fragments):
            print("%2d: %08x, %08x" % (i, off, size))
        print()

        print("lookup:")
        for i, inodenr in enumerate(self.inodemap):
            print("%2d: i:%08x" % (i, inodenr))
        print()

        print("inodes:")
        for i in range(self.nr_inodes):
            o = self.inodemap[i]
            inode = self.readinode(o)
            print("#%04x, i:%08x -> %s -- %s" % (i, o, inode.hdr, inode))
        print()

        print("direntries:")
        for i in range(self.nr_inodes):
            o = self.inodemap[i]
            inode = self.readinode(o)
            if inode.hdr.type in (SQUASHFS_DIR_TYPE, SQUASHFS_LDIR_TYPE):
                for ent in self.readdir(inode.start_block, inode.offset, inode.file_size - 3):
                    print(ent)
        print()


def processfile(args, fh):
    fs = SquashFs(fh)

    if args.savedir:
        fs.savefiles(fs.root_inode, args.savedir)
    elif args.dump:
        fs.dumpinfo()
    else:
        fs.listfiles(fs.root_inode)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='SQUASHFS dumper.')
    parser.add_argument('--offset', '-o', type=str, help="where in the file the SquashFS is located")
    parser.add_argument('--savedir', '-d', type=str, help="where to extract the files to")
    parser.add_argument('--dump', action='store_true', help="verbose dump of all fs contents")
    parser.add_argument('FILES', type=str, nargs='+', help="list of images to use")
    args = parser.parse_args()

    if args.offset:
        args.offset = int(args.offset, 0)
    else:
        args.offset = 0

    for fn in args.FILES:
        with open(fn, "rb") as fh:
            if args.offset:
                fh = OffsetReader(fh, args.offset)
            processfile(args, fh)


if __name__ == '__main__':
    main()
