local hfs = require "horvenfs"

if not fs.exists("test") then
  hfs.buildPartition("test")
  hfs.mountPartition("test","a")
  hfs.fs.clone(".","a")
else
  hfs.mountPartition("test","a")
end

term.clear()
term.setCursorPos(1,1)
term.setTextColor(colors.blue)
print( string.format("Mounted Partitions: %s", table.concat(hfs.list(), ", ")) )
term.setTextColor(colors.white)
print( table.concat(hfs.list("a"), ", ") )