-- Example Startup
local hfs = require "horvenfs"

if not fs.exists("test") then
  -- Builds a partition of your entire file system
  hfs.buildPartition("test")
  hfs.mountPartition("test")
  parallel.waitForAny(function()
    hfs.fs.clone(".","test")
  end,function()
    local t = os.clock()
    while true do
      term.clear()
      term.setCursorPos(1,1)
      term.setTextColor(colors.yellow)
      print(string.format("Cloning '.' into HFS (Time Elapsed %ss)",os.clock()-t))
      sleep(0)
    end
  end)
else
  hfs.mountPartition("test")
end

term.clear()
term.setCursorPos(1,1)
term.setTextColor(colors.green)
print( string.format("Mounted Partitions: %s", table.concat(hfs.list(), " ")) )
term.setTextColor(colors.white)
print( table.concat(hfs.list("test"), " ") )