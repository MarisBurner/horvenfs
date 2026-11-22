local hfs = require "horvenfs"
hfs.mountPartition("test")
hfs.mkdir("ada")

term.clear()
term.setCursorPos(1,1)
print( table.concat(hfs.list()) )
print( table.concat(hfs.list("test")) )