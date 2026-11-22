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

local function buildHasher()
  -- From http://pastebin.com/gsFrNjbt linked from http://www.computercraft.info/forums2/index.php?/topic/8169-sha-256-in-pure-lua/

  --
  --  Adaptation of the Secure Hashing Algorithm (SHA-244/256)
  --  Found Here: http://lua-users.org/wiki/SecureHashAlgorithm
  --
  --  Using an adapted version of the bit library
  --  Found Here: https://bitbucket.org/Boolsheet/bslf/src/1ee664885805/bit.lua
  --

  local MOD = 2 ^ 32
  local MODM = MOD - 1

  local function memoize(f)
    local mt = {}
    local t = setmetatable({}, mt)
    function mt:__index(k)
      local v = f(k)
      t[k] = v
      return v
    end

    return t
  end

  local function make_bitop_uncached(t, m)
    local function bitop(a, b)
      local res, p = 0, 1
      while a ~= 0 and b ~= 0 do
        local am, bm = a % m, b % m
        res = res + t[am][bm] * p
        a = (a - am) / m
        b = (b - bm) / m
        p = p * m
      end
      res = res + (a + b) * p
      return res
    end
    return bitop
  end

  local function make_bitop(t)
    local op1 = make_bitop_uncached(t, 2 ^ 1)
    local op2 = memoize(function(a) return memoize(function(b) return op1(a, b) end) end)
    return make_bitop_uncached(op2, 2 ^ (t.n or 1))
  end

  local bxor1 = make_bitop({ [0] = { [0] = 0, [1] = 1 }, [1] = { [0] = 1, [1] = 0 }, n = 4 })

  local function bxor(a, b, c, ...)
    local z = nil
    if b then
      a = a % MOD
      b = b % MOD
      z = bxor1(a, b)
      if c then z = bxor(z, c, ...) end
      return z
    elseif a then
      return a % MOD
    else
      return 0
    end
  end

  local function band(a, b, c, ...)
    local z
    if b then
      a = a % MOD
      b = b % MOD
      z = ((a + b) - bxor1(a, b)) / 2
      if c then z = bit32_band(z, c, ...) end
      return z
    elseif a then
      return a % MOD
    else
      return MODM
    end
  end

  local function bnot(x) return (-1 - x) % MOD end

  local function rshift1(a, disp)
    if disp < 0 then return lshift(a, -disp) end
    return math.floor(a % 2 ^ 32 / 2 ^ disp)
  end

  local function rshift(x, disp)
    if disp > 31 or disp < -31 then return 0 end
    return rshift1(x % MOD, disp)
  end

  local function lshift(a, disp)
    if disp < 0 then return rshift(a, -disp) end
    return (a * 2 ^ disp) % 2 ^ 32
  end

  local function rrotate(x, disp)
    x = x % MOD
    disp = disp % 32
    local low = band(x, 2 ^ disp - 1)
    return rshift(x, disp) + lshift(low, 32 - disp)
  end

  local k = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  }

  local function str2hexa(s)
    return (string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end))
  end

  local function num2s(l, n)
    local s = ""
    for i = 1, n do
      local rem = l % 256
      s = string.char(rem) .. s
      l = (l - rem) / 256
    end
    return s
  end

  local function s232num(s, i)
    local n = 0
    for i = i, i + 3 do n = n * 256 + string.byte(s, i) end
    return n
  end

  local function preproc(msg, len)
    local extra = 64 - ((len + 9) % 64)
    len = num2s(8 * len, 8)
    msg = msg .. "\128" .. string.rep("\0", extra) .. len
    assert(#msg % 64 == 0)
    return msg
  end

  local function initH256(H)
    H[1] = 0x6a09e667
    H[2] = 0xbb67ae85
    H[3] = 0x3c6ef372
    H[4] = 0xa54ff53a
    H[5] = 0x510e527f
    H[6] = 0x9b05688c
    H[7] = 0x1f83d9ab
    H[8] = 0x5be0cd19
    return H
  end

  local function digestblock(msg, i, H)
    local w = {}
    for j = 1, 16 do w[j] = s232num(msg, i + (j - 1) * 4) end
    for j = 17, 64 do
      local v = w[j - 15]
      local s0 = bxor(rrotate(v, 7), rrotate(v, 18), rshift(v, 3))
      v = w[j - 2]
      w[j] = w[j - 16] + s0 + w[j - 7] + bxor(rrotate(v, 17), rrotate(v, 19), rshift(v, 10))
    end

    local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for i = 1, 64 do
      local s0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
      local maj = bxor(band(a, b), band(a, c), band(b, c))
      local t2 = s0 + maj
      local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local t1 = h + s1 + ch + k[i] + w[i]
      h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2
    end

    H[1] = band(H[1] + a)
    H[2] = band(H[2] + b)
    H[3] = band(H[3] + c)
    H[4] = band(H[4] + d)
    H[5] = band(H[5] + e)
    H[6] = band(H[6] + f)
    H[7] = band(H[7] + g)
    H[8] = band(H[8] + h)
  end

  local function sha256(msg)
    msg = preproc(msg, #msg)
    local H = initH256({})
    for i = 1, #msg, 64 do digestblock(msg, i, H) end
    return str2hexa(num2s(H[1], 4) .. num2s(H[2], 4) .. num2s(H[3], 4) .. num2s(H[4], 4) ..
      num2s(H[5], 4) .. num2s(H[6], 4) .. num2s(H[7], 4) .. num2s(H[8], 4))
  end

  return sha256
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

  local function rencode(str, c)
    local r = str
    while c > 0 do
      r = encode(str)
      c = c - 1
    end
    return r
  end

  local function rdecode(str, c)
    local r = str
    while c > 0 do
      r = decode(str)
      c = c - 1
    end
    return r
  end

  return { rdecode = rdecode, rencode = rencode, encode = encode, decode = decode, serialize = serialize, deserialize = deserialize }
end

local function writeFile(path, data)
  local fl = fs.open(path, "w")
  local d = tostring(type(data) == "table" and textutils.serialize(data, { compact = true }) or data)
  fl.write(d)
  fl.close()
end

local function writeCompFile(path, data)
  -- File write with Compression
  local fl = fs.open(path, "w")
  local d = tostring(type(data) == "table" and textutils.serialize(data, { compact = true }) or data)
  fl.write(lib.compressor.rencode(d,3)) -- Compress it 3 times for maximum saves
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

local function readCompFile(path)
  return lib.compressor.rdecode(readFile(path),3)
end

local function readCompFileT(path)
  return textutils.unserialise(readCompFile(path))
end

lib.compressor = buildCompressor() -- compressor.encode, compressor.decode
lib.sha256 = buildHasher()

local parts = {} -- Partition Paths
local heir = {} -- Filesystem Heirarchy

local function reverseTable(t)
    local i, j = 1, #t
    while i < j do
        t[i], t[j] = t[j], t[i]
        i = i + 1
        j = j - 1
    end
    return t
end

local function pathRemoveFirst(path)
  return path:gsub("^[^/]+/", "")
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

local function pathExists(path)
  local p = getPath(path)
  return type(p) ~= "nil"
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

local function isPartition(path)
  return fs.getDir(path) == ""
end

local function pathPartition(path)
  -- Gets partition of disk (First directory of path)
  while not isPartition(path) do
    path = fs.getDir(path)
  end
  return path
end

local function writePath(path,data)
  -- Only meant to change disk partition block heirs, not the disk partitions
  -- Doesn't overwrite
  path = fs.combine(path) -- Sanitize to Absolute Path
  local p = getPath(fs.getDir(path))
  if isPartition(path) or type(p) ~= "table" then
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

local function setPath(path,data)
  -- Only meant to change disk partition block heirs, not the disk partitions
  -- Made to overwrite
  path = fs.combine(path) -- Sanitize to Absolute Path
  local p = getPath(fs.getDir(path))
  if isPartition(path) or type(p) ~= "table"  then
    return false
  else
    local nm = fs.getName(path)
    p[nm] = data
    return true
  end
end

function lib.buildPartition(dir, name)
  -- Sets up a new hfs partition directory
  assert(not fs.exists(dir), "Trying to build new partition on existing path")

  fs.makeDir(dir)
  writeFile(fs.combine(dir, ".hfs"), {
    vers = 1,
    name = tostring(name or fs.getName(dir))
  }) -- Metadata
  writeCompFile(fs.combine(dir, ".heir"), {}) -- FS Heirarchy
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
  heir[name] = readCompFileT(fs.combine(dir, ".heir"))
  parts[name] = dir
end

function lib.unmount(name)
  heir[name] = nil
  parts[name] = nil
end

function lib.updateHeir(name)
  if heir[name] then
    writeCompFile(fs.combine(parts[name],".heir"),heir[name])
  end
end

function lib.isDir(path)
  local d = getPath(path)
  return type(d) == "table"
end

function lib.exists(path)
  local d = getPath(path)
  return type(d) ~= "nil"
end

function lib.mkdir(path)
  local suc = writePath(path,{})
  if suc then
    lib.updateHeir(pathPartition(path))
  end
  return suc
end

local function getBlockData(path)
  -- Returns block data
  path = fs.combine(path) -- Sanitize Path
  assert(not isPartition(path),"No block in partition",0)
  assert(lib.isDir(fs.getDir(path)),"Block must exist in directory",0)
  local bid = lib.sha256(pathRemoveFirst(path))
  -- Clean Path, Block ID, Block Path
  return path, bid, fs.combine(parts[pathPartition(path)],".blks",bid)
end

local function deleteBlock(path)
  local npath, bid, bpath = getBlockData(path)
  fs.delete(bpath)
end

local function writeBlock(path,data)
  local npath, bid, bpath = getBlockData(path)
  writeCompFile(bpath,data)
end

local function readBlock(path)
  local npath, bid, bpath = getBlockData(path)
  assert(fs.exists(bpath),"Cannot read: Block doesn't exist",0)
  return readCompFile(bpath)
end

local function existsBlock(path)
  local npath, bid, bpath = getBlockData(path)
  return fs.exists(bpath)
end

function lib.delete(path)
  local isDir = lib.isDir(path)
  local suc = deletePath(path)
  if suc then
    if not isDir then
      -- Clear Block
      deleteBlock(path)
    end
    lib.updateHeir(pathPartition(path))
  end
  return suc
end

local function referenceBlock(path,opath)
  -- Create a reference to a Block (Also supports linking other blocks)
  local npath, bid, bpath = getBlockData(opath)
  return setPath(path,bid)
end

function lib.open(path, mode)
  assert(not isPartition(path), "Cannot open a partition as file data",0)
  assert(lib.isDir(fs.getDir(path)), "Trying to open file in directory that doesn't exist",0)
  local dir = getPath(fs.getDir(path))
  local pt = pathPartition(path)
  local handle = {}

  if mode == "w+" or mode == "w" then
    -- Create fresh block
    writeBlock(path, "")
    assert(referenceBlock(path,path), "File open: Failed to reserve block")
  else
    -- If not, assert the path exists
    assert(existsBlock(path),"Cannot open, file doesn't exist")
  end

  if mode == "r+" or mode == "r" or mode == "w+" then
    function handle.readAll()
      return readBlock(path)
    end
  end

  if mode == "r+" or mode == "w" or mode == "w+" then
    function handle.write(data)
      writeBlock(path,tostring(data))
    end
  end

  function handle.close()
    lib.updateHeir(pt)
    handle = nil
  end

  return handle
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

lib.fs = {} -- Library for interacting with the builtin FS

function lib.fs.cloneHFS(dir,part)
  local function c(a,d)
  end
end

if not isRequired() then
  local c = args[1]

  if c == "build" then
    lib.buildPartition(fs.combine(shell.resolve("."), args[2]), args[3])
  elseif c == "clonefs" then
    lib.buildPartition(fs.combine(shell.resolve("."), args[3]))
    lib.mountPartition(fs.combine(shell.resolve("."), args[3]),"d")
    lib.fs.cloneHFS(fs.combine(shell.resolve("."), args[2]),"d")
  else
    error(string.format("Unrecognized HFS Command: '%s'", c),0)
  end
end

return lib