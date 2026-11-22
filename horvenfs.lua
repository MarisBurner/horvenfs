-- Horven File System API
-- Made by Mari

local args = { ... }
local lib = {}

local function isRequired()
  local level = 2
  while true do
    local info = debug.getinfo(level, "f")
    if not info then break end
    if info.func == require then
      return true
    end
    level = level + 1
  end
  return false
end

local function tableKeys(tbl)
  local keys = {}
  for k, _ in pairs(tbl) do
    keys[#keys + 1] = k
  end
  return keys
end

local function tableMap(tbl,fn)
  local r = {}
  for k, v in pairs(tbl) do
    r[k] = fn(v,k)
  end
  return r
end

local function buildCompressor()
  -- Compact table serializer + LZSS compressor for Lua 5.1
  local floor, char, byte, concat = math.floor, string.char, string.byte, table.concat

  ---------------------------------------------------------------- serializer
  -- Tags: 0 nil, 1 false, 2 true, 3 +int, 4 -int, 5 +float, 12 -float,
  --       6 new string, 7 string ref, 8 table, 9 inf, 10 -inf, 11 nan,
  --       16..255 = small integer 0..239 in one byte
  local function serialize(root)
    local o, n, seen, ns, active = {}, 0, {}, 0, {}
    local function b(x)
      n = n + 1; o[n] = char(x)
    end
    local function varint(x)
      while x >= 128 do
        b(x % 128 + 128); x = floor(x / 128)
      end
      b(x)
    end
    local function ser(x)
      local t = type(x)
      if x == nil then
        b(0)
      elseif t == "boolean" then
        b(x and 2 or 1)
      elseif t == "number" then
        if x ~= x then
          b(11)
        elseif x == math.huge then
          b(9)
        elseif x == -math.huge then
          b(10)
        elseif x % 1 == 0 and x > -2 ^ 53 and x < 2 ^ 53 then
          if x >= 0 and x < 240 then
            b(16 + x)
          elseif x > 0 then
            b(3); varint(x)
          else
            b(4); varint(-x)
          end
        else -- float: mantissa * 2^exp, trailing zero bits stripped
          local neg = x < 0
          if neg then x = -x end
          local m, e = math.frexp(x)
          m, e = floor(m * 2 ^ 53), e - 53
          while m % 2 == 0 do
            m = m / 2; e = e + 1
          end
          b(neg and 12 or 5); varint(m)
          varint(e >= 0 and e * 2 or -e * 2 - 1)
        end
      elseif t == "string" then
        local id = seen[x]
        if id then
          b(7); varint(id)
        else
          seen[x] = ns; ns = ns + 1
          b(6); varint(#x); n = n + 1; o[n] = x
        end
      elseif t == "table" then
        if active[x] then error("cyclic table") end
        active[x] = true
        local len = #x
        b(8); varint(len)
        for i = 1, len do ser(x[i]) end
        for k, v in pairs(x) do
          if not (type(k) == "number" and k % 1 == 0 and k >= 1 and k <= len) then
            ser(k); ser(v)
          end
        end
        b(0) -- end of hash part
        active[x] = nil
      else
        error("cannot serialize " .. t)
      end
    end
    ser(root)
    return concat(o)
  end

  local function deserialize(s)
    local p, strs, ns = 1, {}, 0
    local function varint()
      local r, m = 0, 1
      while true do
        local c = byte(s, p); p = p + 1
        if c < 128 then return r + c * m end
        r = r + (c - 128) * m; m = m * 128
      end
    end
    local function de()
      local t = byte(s, p); p = p + 1
      if t >= 16 then
        return t - 16
      elseif t == 0 then
        return nil
      elseif t == 1 then
        return false
      elseif t == 2 then
        return true
      elseif t == 3 then
        return varint()
      elseif t == 4 then
        return -varint()
      elseif t == 5 or t == 12 then
        local m, z = varint(), varint()
        local x = math.ldexp(m, z % 2 == 0 and z / 2 or -(z + 1) / 2)
        return t == 12 and -x or x
      elseif t == 9 then
        return math.huge
      elseif t == 10 then
        return -math.huge
      elseif t == 11 then
        return 0 / 0
      elseif t == 6 then
        local l = varint()
        local str = s:sub(p, p + l - 1); p = p + l
        strs[ns] = str; ns = ns + 1
        return str
      elseif t == 7 then
        return strs[varint()]
      elseif t == 8 then
        local tbl = {}
        for i = 1, varint() do tbl[i] = de() end
        while byte(s, p) ~= 0 do
          local k = de(); tbl[k] = de()
        end
        p = p + 1
        return tbl
      end
      error("bad tag " .. t)
    end
    return de()
  end

  ---------------------------------------------------------------- LZSS
  -- Groups of 8 items behind a flag byte (bit set = literal byte).
  -- Match = 2 bytes: 12-bit distance (1..4096), 4-bit length (3..18).
  local function lzCompress(s)
    local n, out, grp, flag, cnt, head = #s, {}, {}, 0, 0, {}
    local function flush()
      if cnt > 0 then
        out[#out + 1] = char(flag) .. concat(grp)
        grp, flag, cnt = {}, 0, 0
      end
    end
    local function put(lit, a, c)
      if lit then flag = flag + 2 ^ cnt end
      grp[#grp + 1] = a
      if c then grp[#grp + 1] = c end
      cnt = cnt + 1
      if cnt == 8 then flush() end
    end
    local function ins(p)
      if p + 2 <= n then
        local k = s:sub(p, p + 2)
        local l = head[k]
        if l then l[#l + 1] = p else head[k] = { p } end
      end
    end
    local i = 1
    while i <= n do
      local bl, bd = 0, 0
      if i + 2 <= n then
        local l = head[s:sub(i, i + 2)]
        if l then
          for j = #l, math.max(1, #l - 23), -1 do
            local d = i - l[j]
            if d > 4096 then break end
            local k = 0
            while k < 18 and i + k <= n and byte(s, l[j] + k) == byte(s, i + k) do
              k = k + 1
            end
            if k > bl then bl, bd = k, d end
            if k == 18 then break end
          end
        end
      end
      if bl >= 3 then
        local v = (bd - 1) * 16 + bl - 3
        put(false, char(floor(v / 256)), char(v % 256))
        for q = i, i + bl - 1 do ins(q) end
        i = i + bl
      else
        put(true, s:sub(i, i)); ins(i); i = i + 1
      end
    end
    flush()
    return concat(out)
  end

  local function lzDecompress(s)
    local o, n, p, len = {}, 0, 1, #s
    while p <= len do
      local f = byte(s, p); p = p + 1
      for bit = 0, 7 do
        if p > len then break end
        if floor(f / 2 ^ bit) % 2 == 1 then
          n = n + 1; o[n] = s:sub(p, p); p = p + 1
        else
          local v = byte(s, p) * 256 + byte(s, p + 1); p = p + 2
          local d, l = floor(v / 16) + 1, v % 16 + 3
          for _ = 1, l do
            o[n + 1] = o[n + 1 - d]; n = n + 1
          end
        end
      end
    end
    return concat(o)
  end

  --public API
  local function encode(tbl)
    local raw = serialize(tbl)
    local c = lzCompress(raw)
    if #c < #raw then return "\1" .. c end
    return "\0" .. raw -- never grows by more than 1 byte
  end

  local function decode(str)
    local body = str:sub(2)
    if str:sub(1, 1) == "\1" then body = lzDecompress(body) end
    return deserialize(body)
  end

  return { encode = encode, decode = decode, serialize = serialize, deserialize = deserialize }
end

local function writeFile(path, data)
  local fl = fs.open(path, "w")
  fl.write(type(data) == "table" and textutils.serialize(data, { compact = true }) or data)
  fl.close()
end

local function readFile(path)
  local fl = fs.open(path, "r")
  local r = fl.readAll()
  fl.close()
  return r
end

local function readFileT(path)
  return textutils.unserialise(readFile(path))
end

lib.compressor = buildCompressor() -- compressor.encode, compressor.decode
local parts = {}
local heir = {}

local function reverseTable(t)
    local i, j = 1, #t
    while i < j do
        t[i], t[j] = t[j], t[i]
        i = i + 1
        j = j - 1
    end
    return t
end

local function pathTable(path)
  -- Turn Path into table to traceback
  local npath = fs.combine(path)
  local r = {}
  while fs.getName(npath) ~= "" do
    r[#r+1] = fs.getName(npath)
    npath = fs.getDir(npath)
  end
  return reverseTable(r)
end

local function pathExists(path)
  local ps = pathTable(path)
  local r = heir
  for _, d in ipairs(ps) do
    if type(r) == "table" then
      r = r[d]
    else
      return false
    end
  end
  return not not r
end

local function getPath(path)
  -- Get Data of Path in Heirarchy
  local ps = pathTable(path)
  if #ps == 0 then
    return heir
  end
  local nm = table.remove(ps)
  local r = heir
  for _, d in ipairs(ps) do
    if type(r) == "table" then
      r = r[d]
    else
      return nil
    end
  end
  return r[nm]
end

local function deletePath(path)
  path = fs.combine(path) -- Sanitize to Absolute Path
  local p = getPath(fs.getDir(path))
  if p == heir or type(p) ~= "table" then
    return false
  else
    p[fs.getName(path)] = nil
    return true
  end
end

local function setPath(path,data)
  -- Only meant to change disk partition block heirs, not the disk partitions
  path = fs.combine(path) -- Sanitize to Absolute Path
  local p = getPath(fs.getDir(path))
  if p == heir or type(p) ~= "table" then
    return false
  else
    local nm = fs.getName(path)
    if p[nm] then
      -- Overlapping Data (Requires Delete First)
      return false
    else
      p[nm] = data
      return true
    end
  end
end

local function pathPartition(path)
  -- Gets partition of disk (First directory of path)
  return pathTable(path)[1] or ""
end

function lib.buildPartition(dir, name)
  -- Sets up a new hfs partition directory
  assert(not fs.exists(dir), "Trying to build new partition on existing path")

  fs.makeDir(dir)
  writeFile(fs.combine(dir, ".hfs"), {
    vers = 1,
    name = tostring(name or fs.getName(dir))
  }) -- Metadata
  writeFile(fs.combine(dir, ".heir"), {}) -- FS Heirarchy
  fs.makeDir(fs.combine(dir, ".blks")) -- Compressed Blocks
end

function lib.isHFS(dir)
  return fs.exists(fs.combine(dir,".hfs")) and fs.exists(fs.combine(dir,".heir")) and fs.exists(fs.combine(dir,".blks"))
end

function lib.mountPartition(dir,name)
  -- Add FileSystem Heirarchy to Heirarchy
  assert(lib.isHFS(dir), "Directory is not an HFS partition")
  if type(name) == "string" then
    assert(not heir[name], "Overlapping mount paths")
  else
    name = readFileT(fs.combine(dir,".hfs")).name
    local i = 1
    while heir[name] do
      name = string.format("%s%n",name,i)
      i = i + 1
    end
  end
  heir[name] = readFileT(fs.combine(dir, ".heir"))
  parts[name] = dir
end

function lib.unmount(name)
  heir[name] = nil
  parts[name] = nil
end

function lib.updateHeir(name)
  if heir[name] then
    writeFile(fs.combine(parts[name],".heir"),heir[name])
  end
end

function lib.mkdir(path)
  local suc = setPath(path,{})
  if suc then
    lib.updateHeir(path)
  end
  return suc
end

function lib.delete(path)
  return deletePath(path)
end

function lib.list(path,abs)
  path = fs.combine(path or ".")
  local dir = getPath(path)
  if type(dir) == "table" then
    local ht = tableKeys(dir)
    if abs then
      local full = fs.getDir(path)
      return tableMap(ht,function(p)
        return fs.combine(full,p)
      end)
    end
    return ht
  end
end

if not isRequired() then
  local c = args[1]

  if c == "build" then
    lib.buildPartition(fs.combine(shell.resolve("."), args[2]), args[3])
  else
    error(string.format("Unrecognized HFS Command: '%s'", c),0)
  end
end

return lib