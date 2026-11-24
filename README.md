# HorvenFS
### What is HorvenFS?
It's a virtual file system format made to compress large directories and files in ComputerCraft.

## Quick Start

Install horvenfs using this command
```
wget https://raw.githubusercontent.com/MarisBurner/horvenfs/main/horvenfs.lua /horvenfs.lua
```

After you've installed the **horvenfs.lua** file into your root directory, you can start building a partition.

Type this command to build an HVFS partition:
```
horvenfs build <your partition directory> [optional partition meta name]
```

To learn more, check out the [Documentation](https://github.com/MarisBurner/horvenfs/wiki/)

## Example Program
A quick example of mounting a partition and writing to a file
```lua
local hvfs = require "horvenfs"

hvfs.mountPartition("test","p1")

local fl = hvfs.open("p1/test.txt","w")
fl.write("Hello World!")
fl.close()

hvfs.fs.grab("p1/test.txt","test.txt") -- This function grabs something from HVFS and loads it into the regular FS
```

### Q/A
Q: If I have a lot of small files, will the file system still be able to compress it?

**A: Yes! The new algorithm uses 3 times LZ77/Huffman compression. It reduces even relatively small high-entropy files down by 16% (Via recent benchmark).**

```
= FILE COPYING =
Sizes:
High = 1MB | Mid = 100KB | Low = 5KB

FS AVG Time (seconds)
High - 0.00611
Mid - 0.00154
Low - 0.000701

HVFS AVG Time (seconds)
High - 3.952
Mid - 0.43868
Low - 0.09

HVFS Size Ratio Diff (Compressed/Uncompressed - 100%)
High - -17.873%
Mid - -17.898%
Low - -16.67578%
```

Q: Does it support multi-disk filesystems?

**A: Technically, Yes. Whenever you mount a file system, it turns it into a partition directory in the API's heirarchy. You can have multiple disks which have a unique partition directory in that heirarchy and name them whatever you want. The only limitation is that the block ID's (The ID the VFS uses to find the blocks) are tied to the partition directory. You can't mount two disks into the same partition directory, and you can't reference blocks from outside partitions in a partition.**

Q: Does it take advantage of any RCC modpack functions such as the Cryptographic Accelerator?

**A: Not in the current release. I first had the intention of implementing builtin encryption to the file system and its blocks, but that might be for a future release. It's not currently included. The compression algorithm, however, comes packaged with the API, so no need for any outside peripherals.**

Q: How similar is the VFS layer to the normal FS API?

**A: They share a lot of similarities. One big thing I did not end up finishing in the current release are wildcard paths (i.e. /rom/\*). That's for a future update. Everything else though, such as delete, list, makeDir, open, and exists function as normal with some slight limitations. For now, it's about 75% parity.**