# HorvenFS
### What is HorvenFS?
It's a virtual file system made to compress large directories and files in ComputerCraft.

## Quick Start
After you've installed the **horvenfs.lua** file into your root directory, you can start building a partition.

You can type this command:
```
horvenfs build <your partition directory> [optional partition meta name]
```

Other useful commands to use:
```
horvenfs clear <partition directory>
horvenfs ls <partition directory> <path in partition>
horvenfs cat <partition directory> <path in partition>
```

## Example Program
A quick example of mounting a partition and writing to a file
```lua
local hfs = require "horvenfs"

hfs.mountPartition("test","p1")

local fl = hfs.open("p1/test.txt","w")
fl.write("Hello World!")
fl.close()

hfs.fs.grab("p1/test.txt","test.txt") -- This function grabs something from HFS and loads it into the regular FS
```

### Q/A
Q: If I have a lot of small files, will the file system still be able to compress it?

**A: No, the compression algorithm works only on blocks of data instead of the entirety of the file system. On smaller files with less data to compress, it might add a small bloat of 3 bytes due to the algorithm trying to compress it but not having enough information to compress.**

Q: Does it support multi-disk filesystems?

**A: Technically, Yes. Whenever you mount a file system, it turns it into a partition directory in the API's Heirarchy. You can have multiple disks which have a unique partition directory in that heirarchy and name them whatever you want. The only limitation is that the block ID's (The ID the VFS uses to find the blocks) are tied to the partition directory. You can't mount two disks into the same partition directory, and you can't reference blocks from outside partitions from one partition.**

Q: Does it take advantage of any RCC modpack functions such as the Cryptographic Accelerator?

**A: Not in the current release. I first had the intention of implementing builtin encryption to the file system and its blocks, but that might be for a future release. It's not currently included. The compression algorithm, however, comes packaged with the API, so no need for any outside peripherals.**

Q: How similar is the VFS layer to the normal FS API?

**A: They share a lot of similarities. The only things I did not end up finishing in the current release are wildcard paths (i.e. /rom/\*). That's for a future update. Everything else though, such as delete, list, mkdir, open, and exists function as normal.**