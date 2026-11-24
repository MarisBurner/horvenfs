-- Example Startup
local hvfs = require "horvenfs"

if not fs.exists("test") then
  -- Builds a partition of your entire file system
  hvfs.buildPartition("test")
  hvfs.mountPartition("test")
  parallel.waitForAny(function()
    hvfs.fs.clone(".","test")
  end,function()
    local t = os.clock()
    while true do
      term.clear()
      term.setCursorPos(1,1)
      term.setTextColor(colors.yellow)
      print(string.format("Cloning '.' into HVFS (Time Elapsed %ss)",os.clock()-t))
      sleep(0)
    end
  end)
else
  hvfs.mountPartition("test")
end

term.clear()
term.setCursorPos(1,1)
term.setTextColor(colors.green)
print( string.format("Mounted Partitions: %s", table.concat(hvfs.list(), " ")) )
term.setTextColor(colors.white)
print( table.concat(hvfs.list("test"), " ") )