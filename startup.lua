local hfs = require "horvenfs"
hfs.mountPartition("test","a")

term.clear()
term.setCursorPos(1,1)

local function writeFile(path,data)
  local fl = hfs.open(path,"w")
  fl.write(data)
  fl.close()
end

writeFile("a/test.txt","Hello, World!")
writeFile("a/program.lua","")

print( table.concat(hfs.list()) )
print( table.concat(hfs.list("a"),", ") )