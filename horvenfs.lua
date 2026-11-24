-- Horven File System API
-- Made by Mari

local fs = fs
local args = { ... }
local lib = {}
lib.version = 1

assert(fs, "HorvenFS requires filesystem access!")

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

local function tableFlip(tbl)
  local r = {}
  for k, v in pairs(tbl) do
    r[v] = k
  end
  return r
end

local function tableKeys(tbl)
  local keys = {}
  for k, _ in pairs(tbl) do
    keys[#keys + 1] = k
  end
  return keys
end

local function tableMap(tbl, fn)
  local r = {}
  for k, v in pairs(tbl) do
    r[k] = fn(v, k)
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
  -- Minimized Table serializer + LZ77/Huffman compressor for CC (Lua 5.1)

  local a, b, c, d, e = math.floor, string.char, string.byte, string.sub, table.concat; local f, g = table.sort, math
  .log; local unpack = unpack or table.unpack; local h = math.huge; local type, pairs, error, tostring, select = type,
      pairs, error, tostring, select; local i = math.frexp or
  function(j)
    if j == 0 then return 0, 0 end; local k = a(g(j) / g(2)) + 1; local l = j / 2 ^ k; if l >= 1 then
      l = l / 2; k = k + 1
    elseif l < 0.5 then
      l = l * 2; k = k - 1
    end; return l, k
  end; local m = math.ldexp or function(l, k) return l * 2 ^ k end; local n, o = os.epoch, os.clock; local p = os
  .queueEvent; local q = os.pullEventRaw or os.pullEvent; local function r()
    if n then return n("utc") / 1000 end; return o()
  end; local s = {}
  for t = 0, 40 do s[t] = 2 ^ t end; local u = {}
  for t = 0, 255 do u[t] = b(t) end; local v = 20000; local w = 400000; local x = 1; local y, z, A = 0, 0, r()
  local function B(...) return { n = select("#", ...), ... } end; local function C()
    if not p then return end; p("lz_yield")
    local D, E = {}, 0; while true do
      local k = B(q())
      if k[1] == "lz_yield" then break end; if k[1] == "terminate" then error("Terminated", 0) end; E = E + 1; D[E] = k
    end; for t = 1, E do
      local k = D[t]
      p(unpack(k, 1, k.n))
    end
  end; local function F()
    z = z + y; y = 0; if z >= w or r() - A > x then
      z = 0; C()
      A = r()
    end
  end; local function G(H)
    local I, E = {}, 0; local J, K = {}, 0; local L = {}
    local function M(j)
      while j >= 128 do
        local N = j % 128; E = E + 1; I[E] = u[N + 128]
        j = (j - N) / 128
      end; E = E + 1; I[E] = u[j]
    end; local function O(j)
      y = y + 1; if y >= v then F() end; local P = type(j)
      if P == "number" then if j >= 0 and j < 240 and j % 1 == 0 then
          E = E + 1; I[E] = u[16 + j]
        elseif j ~= j then
          E = E + 1; I[E] = u[11]
        elseif j == h then
          E = E + 1; I[E] = u[9]
        elseif j == -h then
          E = E + 1; I[E] = u[10]
        elseif j % 1 == 0 and j > -2 ^ 53 and j < 2 ^ 53 then
          E = E + 1; if j > 0 then
            I[E] = u[3]
            M(j)
          else
            I[E] = u[4]
            M(-j)
          end
        else
          local Q = j < 0; if Q then j = -j end; local l, k = i(j)
          l, k = a(l * 2 ^ 53), k - 53; while l % 2 == 0 do
            l = l / 2; k = k + 1
          end; E = E + 1; I[E] = Q and u[12] or u[5]
          M(l)
          M(k >= 0 and k * 2 or -k * 2 - 1)
        end elseif P == "string" then
        local R = J[j]
        if R then
          E = E + 1; I[E] = u[7]
          M(R)
        else
          J[j] = K; K = K + 1; E = E + 1; I[E] = u[6]
          M(#j)
          E = E + 1; I[E] = j
        end
      elseif P == "table" then
        if L[j] then error("cyclic table") end; L[j] = true; local S = #j; E = E + 1; I[E] = u[8]
        M(S)
        for t = 1, S do O(j[t]) end; for T, U in pairs(j) do if type(T) ~= "number" or T > S or T < 1 or T % 1 ~= 0 then
            O(T)
            O(U)
          end end; y = y + S; if y >= v then F() end; E = E + 1; I[E] = u[0]
        L[j] = nil
      elseif P == "boolean" then
        E = E + 1; I[E] = j and u[2] or u[1]
      elseif P == "nil" then
        E = E + 1; I[E] = u[0]
      else error("cannot serialize " .. P) end
    end; O(H)
    return e(I)
  end; local function V(W, X)
    X = X or 1; local Y, K = {}, 0; local function M()
      local Z = c(W, X)
      X = X + 1; if not Z then error("truncated or corrupt data") end; if Z < 128 then return Z end; local _, l = Z - 128,
          128; while true do
        Z = c(W, X)
        X = X + 1; if not Z then error("truncated or corrupt data") end; if Z < 128 then return _ + Z * l end; _ = _ +
        (Z - 128) * l; l = l * 128
      end
    end; local function a0()
      y = y + 1; if y >= v then F() end; local P = c(W, X)
      X = X + 1; if not P then error("truncated or corrupt data") end; if P >= 16 then return P - 16 elseif P == 7 then return
        Y[M() + 1] elseif P == 6 then
        local a1 = M()
        local j = d(W, X, X + a1 - 1)
        X = X + a1; K = K + 1; Y[K] = j; return j
      elseif P == 8 then
        local N = {}
        for t = 1, M() do N[t] = a0() end; while c(W, X) ~= 0 do
          if X > #W then error("truncated or corrupt data") end; local T = a0()
          N[T] = a0()
        end; X = X + 1; return N
      elseif P == 0 then return nil elseif P == 1 then return false elseif P == 2 then return true elseif P == 3 then return
        M() elseif P == 4 then return -M() elseif P == 5 or P == 12 then
        local l, a2 = M(), M()
        local j = m(l, a2 % 2 == 0 and a2 / 2 or -(a2 + 1) / 2)
        return P == 12 and -j or j
      elseif P == 9 then return h elseif P == 10 then return -h elseif P == 11 then return 0 / 0 end; error("bad tag " ..
      P)
    end; return a0()
  end; local a3, a4 = 65536, 514; local a5, a6 = 274, 32; local a7 = 10; local a8 = 30000; local a9 = 32768; local aa = { 1, 2, 4 }
  local ab = 2048; local ac, ad, ae, af, ag = 16, 16, 128, 1, 64; local ah = { { 4, 8, 32, 0, 8 }, { 8, 12, 64, 1, 24 }, { 16, 16, 128, 1, 64 }, { 32, 32, 514, 2, 514 } }
  local function ai(E)
    local P = ah[E]
    if not P then error("bad level " .. tostring(E)) end; ac, ad, ae, af, ag = P[1], P[2], P[3], P[4], P[5]
  end; local aj = 131072; local function ak(E)
    if type(E) ~= "number" or E < 4096 then error("chunk size must be >= 4096") end; aj = a(E)
  end; local al, am, an, ao = {}, {}, {}, {}
  for Z = 0, 31 do if Z < 4 then
      al[Z] = Z; am[Z] = 0
    else
      local ap = a(Z / 2)
      am[Z] = ap - 1; al[Z] = (2 + Z % 2) * s[ap - 1]
    end end; local function aq(ar)
    if ar < 4 then return ar, 0, 0 end; local as, k = i(ar)
    local ap, N = k - 1, k - 2; return 2 * ap + a(ar / s[N]) % 2, N, ar % s[N]
  end; for ar = 0, a4 - 3 do
    local Z, as, j = aq(ar)
    an[ar] = 256 + Z; ao[ar] = j
  end; local function at(W, E)
    local au = {}
    for t = 1, E, ab do
      local P = { c(W, t, t + ab - 1) }
      local av = t - 1; for T = 1, #P do au[av + T] = P[T] end; y = y + ab; if y >= v then F() end
    end; return au
  end; local function aw(P, E)
    local _, Z = {}, 0; for t = 1, E, ab do
      local ax = t + ab - 1; if ax > E then ax = E end; Z = Z + 1; _[Z] = b(unpack(P, t, ax))
      y = y + ab; if y >= v then F() end
    end; return e(_)
  end; local function ay(az, aA)
    local aB = {}
    for t = 1, aA do aB[t] = az[t] end; while true do
      local aC, l = {}, 0; for t = 1, aA do if aB[t] > 0 then
          l = l + 1; aC[l] = t
        end end; local S = {}
      for t = 1, aA do S[t] = 0 end; if l == 0 then return S end; if l == 1 then
        S[aC[1]] = 1; return S
      end; f(aC, function(aD, au)
        local j, aE = aB[aD], aB[au]
        if j ~= aE then return j < aE end; return aD < au
      end)
      local aF, aG = {}, {}
      for t = 1, l do aF[t] = aB[aC[t]] end; local aH, aI, aJ = 1, l + 1, l; local function aK()
        if aH <= l and (aI > aJ or aF[aH] <= aF[aI]) then
          aH = aH + 1; return aH - 1
        end; aI = aI + 1; return aI - 1
      end; for T = l + 1, 2 * l - 1 do
        local aD = aK()
        local au = aK()
        aF[T] = aF[aD] + aF[au]
        aG[aD] = T; aG[au] = T; aJ = T
      end; local aL, aM = {}, 0; aL[2 * l - 1] = 0; for t = 2 * l - 2, 1, -1 do aL[t] = aL[aG[t]] + 1 end; for t = 1, l do
        local aN = aL[t]
        S[aC[t]] = aN; if aN > aM then aM = aN end
      end; if aM <= 15 then return S end; for t = 1, aA do if aB[t] > 0 then aB[t] = a((aB[t] + 1) / 2) end end
    end
  end; local function aO(S, aA)
    local aP, aQ, Z, aR = {}, {}, 0, {}
    for t = 0, 15 do aP[t] = 0 end; for t = 1, aA do
      local U = S[t]
      if U > 0 then aP[U] = aP[U] + 1 end
    end; for t = 1, 15 do
      Z = (Z + aP[t - 1]) * 2; aQ[t] = Z
    end; for t = 1, aA do
      local U = S[t]
      if U > 0 then
        aR[t] = aQ[U]
        aQ[U] = aQ[U] + 1
      else aR[t] = 0 end
    end; return aR
  end; local function aS(au, aD, a2, aT)
    local k = 0; for _ = 0, aT - 1 do
      local aU, l = {}, 0; for U = 0, 255 do aU[U] = 0 end; for t = aD + _, a2, aT do
        local U = au[t]
        aU[U] = aU[U] + 1; l = l + 1
      end; if l > 0 then
        local aV = g(l)
        for U = 0, 255 do
          local Z = aU[U]
          if Z > 0 then k = k - Z * (g(Z) - aV) end
        end
      end; y = y + l + 300
    end; return k
  end; local function aW(W)
    local E = #W; local au = at(W, E)
    local aX, P, l, aY, aZ = {}, {}, 0, {}, 1; for aD = 1, E, a9 do
      if y >= v then F() end; local a2 = aD + a9 - 1; if a2 > E then a2 = E end; local Z = 1; if af > 0 then
        local a_ = a2; if af == 1 and a_ > aD + 4095 then a_ = aD + 4095 end; local b0 = aS(au, aD, a_, 1) * 0.97; for T = 2, 3 do
          local k = aS(au, aD, a_, aa[T])
          if k < b0 then Z, b0 = T, k end; if y >= v then F() end
        end
      end; aX[#aX + 1] = Z - 1; local aT = aa[Z]
      for _ = 0, aT - 1 do
        if aT > 1 or aZ > 1 then aY[#aY + 1] = l + 1 end; for t = aD + _, a2, aT do
          l = l + 1; P[l] = au[t]
        end
      end; y = y + a2 - aD + 1; aZ = aT
    end; au = P; local b1, b2, b3, b4 = {}, {}, {}, 0; local function b5(X) if X + 2 <= E then
        local T = au[X] * 65536 + au[X + 1] * 256 + au[X + 2]
        b2[X] = b1[T] or 0; b1[T] = X
      end end; local function b6(t)
      if t + 2 > E then return 0, 0 end; local ax = b1[au[t] * 65536 + au[t + 1] * 256 + au[t + 2]]
      if not ax then return 0, 0 end; local b7 = E - t + 1; if b7 > a4 then b7 = a4 end; local b8, b9, ba = 0, 0, ac; repeat
        local aN = t - ax; if aN > a3 then break end; if b8 == 0 or au[ax + b8] == au[t + b8] then
          local T = 3; while T < b7 and au[ax + T] == au[t + T] do T = T + 1 end; y = y + T; if T > b8 then
            b8, b9 = T, aN; if T >= b7 or T >= ae then break end
          end
        end; ax = b2[ax]
        ba = ba - 1
      until ax == 0 or ba == 0; y = y + (ac - ba) * 2; if b8 == 3 and b9 > 4096 then return 0, 0 end; return b8, b9
    end; local function bb(S, bc)
      local Z, as, j = aq(bc - 1)
      b4 = b4 + 1; b3[b4] = an[S - 3] + 512 * (Z + 32 * (ao[S - 3] + 128 * j))
    end; local t, bd, be = 1, {}, 1; local bf = aY[1] or h; local bg, bh = b6(1)
    while t <= E do
      if t >= bf then
        bd[#bd + 1] = b4 + 1; repeat
          be = be + 1; bf = aY[be] or h
        until bf > t
      end; y = y + 2; if y >= v then F() end; if bg >= 3 then
        b5(t)
        local bi, bj = 0, 0; if bg < ad and t < E then bi, bj = b6(t + 1) end; if bi > bg then
          b4 = b4 + 1; b3[b4] = au[t]
          t = t + 1; bg, bh = bi, bj
        else
          bb(bg, bh)
          local bk = bg - 1; if bk > ag then bk = ag end; for N = t + 1, t + bk do b5(N) end; y = y + bk; t = t + bg; bg, bh =
          b6(t)
        end
      else
        b4 = b4 + 1; b3[b4] = au[t]
        b5(t)
        t = t + 1; bg, bh = b6(t)
      end
    end; au, P, b1, b2 = nil, nil, nil, nil; local I, bl, bm, bn = {}, 4, 0, 0; I[1] = a(E / 16777216) % 256; I[2] = a(E /
    65536) % 256; I[3] = a(E / 256) % 256; I[4] = E % 256; local function bo(U, T)
      bm = bm * s[T] + U; bn = bn + T; while bn >= 8 do
        bn = bn - 8; local N = s[bn]
        local _ = bm % N; bl = bl + 1; I[bl] = (bm - _) / N; bm = _
      end
    end; local function bp(S, aA)
      local t = 1; while t <= aA do
        local U = S[t]
        if U > 0 then
          bo(U, 4)
          t = t + 1
        else
          local _ = 1; while _ < 128 and t + _ <= aA and S[t + _] == 0 do _ = _ + 1 end; bo(0, 4)
          bo(_ - 1, 7)
          t = t + _
        end
      end
    end; for T = 1, #aX do bo(aX[T], 2) end; local aD, bq = 1, 1; while aD <= b4 do
      F()
      local a2 = aD + a8 - 1; if a2 > b4 then a2 = b4 end; while bd[bq] and bd[bq] <= aD do bq = bq + 1 end; if bd[bq] and bd[bq] - 1 < a2 then a2 =
        bd[bq] - 1 end; local br, bs = {}, {}
      for N = 1, a5 do br[N] = 0 end; for N = 1, a6 do bs[N] = 0 end; for N = aD, a2 do
        local bt = b3[N]
        if bt < 256 then br[bt + 1] = br[bt + 1] + 1 else
          local aE = bt % 512; br[aE + 1] = br[aE + 1] + 1; local Z = a(bt / 512) % 32; bs[Z + 1] = bs[Z + 1] + 1
        end
      end; y = y + a2 - aD + 1; local bu, bi = ay(br, a5), ay(bs, a6)
      local bv, bw = aO(bu, a5), aO(bi, a6)
      bo(a2 - aD + 1, 16)
      bp(bu, a5)
      bp(bi, a6)
      for N = aD, a2 do
        local bt = b3[N]
        if bt < 256 then bo(bv[bt + 1], bu[bt + 1]) else
          local aE = bt % 512; local _ = (bt - aE) / 512; local Z = _ % 32; _ = (_ - Z) / 32; local bx = _ % 128; local by = (_ - bx) /
          128; local k = am[aE - 256]
          bo(bv[aE + 1] * s[k] + bx, bu[aE + 1] + k)
          k = am[Z]
          bo(bw[Z + 1] * s[k] + by, bi[Z + 1] + k)
        end; y = y + 2; if y >= v then F() end
      end; aD = a2 + 1
    end; if bn > 0 then bo(0, 8 - bn) end; return aw(I, bl)
  end; local function bz(W, bA)
    bA = bA or 1; if #W < bA + 3 then return "" end; local E = ((c(W, bA) * 256 + c(W, bA + 1)) * 256 + c(W, bA + 2)) *
    256 + c(W, bA + 3)
    local X, bm, bn = bA + 4, 0, 0; local bB = #W + 8; local function bC(T)
      while bn < T do
        if X > bB then error("unexpected end of compressed data") end; bm = bm * 256 + (c(W, X) or 0)
        X = X + 1; bn = bn + 8
      end; bn = bn - T; local N = s[bn]
      local _ = bm % N; local j = (bm - _) / N; bm = _; return j
    end; local function bD(aA)
      local S = {}
      for t = 1, aA do S[t] = 0 end; local t = 1; while t <= aA do
        local U = bC(4)
        if U > 0 then
          S[t] = U; t = t + 1
        else t = t + bC(7) + 1 end
      end; return S
    end; local function bE(S, aA)
      local aR = aO(S, aA)
      local bF, bG = {}, {}
      for t = 1, aA do
        local U = S[t]
        if U > 0 then if U <= a7 then
            local aF = s[a7 - U]
            local k = (t - 1) * 16 + U; local bH = aR[t] * aF; for T = 1, aF do bF[bH + T] = k end
          else bG[s[U] + aR[t]] = t - 1 end end
      end; return bF, bG
    end; local function bI(bF, bG)
      local N = s[bn - a7]
      local k = bF[(bm - bm % N) / N + 1]
      local bJ, a1; if k then
        a1 = k % 16; bJ = (k - a1) / 16
      else
        a1 = a7 + 1; repeat
          N = s[bn - a1]
          bJ = bG[s[a1] + (bm - bm % N) / N]
          if bJ then break end; a1 = a1 + 1
        until a1 > 15; if not bJ then error("bad data") end
      end; bn = bn - a1; bm = bm % s[bn]
      return bJ
    end; local aX, bK = {}, 0; for T = 1, a((E + a9 - 1) / a9) do
      aX[T] = bC(2)
      bK = bK + aX[T]
    end; local av, l = {}, 0; while l < E do
      if y >= v then F() end; local aP = bC(16)
      if aP == 0 then error("corrupt compressed data (empty block)") end; local bu, bi = bD(a5), bD(a6)
      local bL, bM = bE(bu, a5)
      local bN, bO = bE(bi, a6)
      y = y + 1500; for as = 1, aP do
        if y >= v then F() end; while bn < 32 do
          if X > bB then error("unexpected end of compressed data") end; bm = bm * 256 + (c(W, X) or 0)
          X = X + 1; bn = bn + 8
        end; local bJ = bI(bL, bM)
        if bJ < 256 then
          l = l + 1; av[l] = bJ; y = y + 1
        else
          bJ = bJ - 256; local bP = am[bJ]
          local ar = al[bJ]
          if bP > 0 then
            local N = s[bn - bP]
            local _ = bm % N; ar = ar + (bm - _) / N; bm = _; bn = bn - bP
          end; while bn < 32 do
            if X > bB then error("unexpected end of compressed data") end; bm = bm * 256 + (c(W, X) or 0)
            X = X + 1; bn = bn + 8
          end; bJ = bI(bN, bO)
          bP = am[bJ]
          local aN = al[bJ]
          if bP > 0 then
            local N = s[bn - bP]
            local _ = bm % N; aN = aN + (bm - _) / N; bm = _; bn = bn - bP
          end; aN = aN + 1; if aN > l then error("corrupt compressed data (bad distance)") end; local bQ = ar + 3; for N = l + 1, l + bQ do av[N] =
            av[N - aN] end; l = l + bQ; y = y + 2 + bQ * 0.25
        end
      end
    end; if bK > 0 then
      local P, N = {}, 0; for t = 1, E do P[t] = 0 end; for T = 1, #aX do
        local aD = (T - 1) * a9 + 1; local a2 = aD + a9 - 1; if a2 > E then a2 = E end; local aT = aa[aX[T] + 1]
        for _ = 0, aT - 1 do for t = aD + _, a2, aT do
            N = N + 1; P[t] = av[N]
          end end; y = y + a2 - aD + 1; if y >= v then F() end
      end; av = P
    end; return aw(av, E)
  end; local function bR(W)
    if #W == 0 then return "" end; return aW(W)
  end; local function bS(W)
    local E = #W; if E < 4096 then return false end; local aU = {}
    for U = 0, 255 do aU[U] = 0 end; for T = 0, 3 do
      local bT = a((E - 1024) * T / 3) + 1; local P = { c(W, bT, bT + 1023) }
      for t = 1, 1024 do
        local U = P[t]
        aU[U] = aU[U] + 1
      end
    end; local k = 0; for U = 0, 255 do
      local Z = aU[U]
      if Z > 0 then
        Z = Z / 4096; k = k - Z * g(Z)
      end
    end; return k / g(2) > 7.9
  end; local function bU(E) return b(a(E / 16777216) % 256, a(E / 65536) % 256, a(E / 256) % 256, E % 256) end; local function bV(
      W, X)
    local aD, au, Z, aN = c(W, X, X + 3)
    return ((aD * 256 + au) * 256 + Z) * 256 + aN
  end; local function bW(W, X)
    local aD, au = 1, 0; for t = X, #W, ab do
      local P = { c(W, t, t + ab - 1) }
      for T = 1, #P do
        aD = aD + P[T]
        au = au + aD
      end; aD = aD % 65521; au = au % 65521; y = y + ab; if y >= v then F() end
    end; return au * 65536 + aD
  end; local function bX(W) if #W < 6 or bW(W, 6) ~= bV(W, 2) then error(
      "checksum mismatch: compressed data was altered or truncated after encoding" ..
      " (storage layer not binary-safe? see encodeText/decodeText)", 0) end end; local function bY(W)
    if #W >= 32 and not bS(W) then
      local Z = bR(W)
      if #Z < #W then return "\7" .. bU(bW(Z, 1)) .. Z end
    end; return "\2" .. W
  end; local function bZ(W)
    local ap = c(W, 1)
    if ap == 7 then
      bX(W)
      return bz(W, 6)
    end; if ap == 3 then return bz(W, 2) end; return d(W, 2)
  end; local function b_(W, c0)
    local c1, c2 = {}, 0; for t = 1, #W, c0 do
      local Z = bY(d(W, t, t + c0 - 1))
      c2 = c2 + 1; c1[c2] = bU(#Z) .. Z
    end; return e(c1)
  end; local function c3(W, X)
    local c1, c2 = {}, 0; local S = #W; while X <= S do
      local a1 = bV(W, X)
      c2 = c2 + 1; c1[c2] = bZ(d(W, X + 4, X + 3 + a1))
      X = X + 4 + a1
    end; return e(c1)
  end; local function c4(U, c5)
    if c5 then ai(c5) end; local c6 = type(U) == "string"
    local _ = c6 and U or G(U)
    local c7 = c6 and 2 or 0; if #_ > aj then return b(c6 and 4 or 5) .. b_(_, aj) end; if #_ >= 32 and not bS(_) then
      local Z = bR(_)
      if #Z < #_ then return b(c6 and 7 or 6) .. bU(bW(Z, 1)) .. Z end
    end; return b(c7) .. _
  end; local function c8(W)
    if type(W) ~= "string" or #W == 0 then error("decode: empty or non-string input", 0) end; local ap = c(W, 1)
    if ap == 7 then
      bX(W)
      return bz(W, 6)
    end; if ap == 6 then
      bX(W)
      return V(bz(W, 6))
    end; if ap == 1 then return V(bz(W, 2)) end; if ap == 3 then return bz(W, 2) end; if ap == 2 then return d(W, 2) end; if ap == 4 then return
      c3(W, 2) end; if ap == 5 then return V(c3(W, 2)) end; return V(W, 2)
  end; local function c9(U, aP, c5)
    if c5 then ai(c5) end; for as = 1, aP do U = c4(U) end; return U
  end; local function ca(U, aP)
    for as = 1, aP do U = c8(U) end; return U
  end; local function cb(W, c0, c5)
    if c5 then ai(c5) end; return "\4" .. b_(W, c0 or aj)
  end; local function cc(W)
    if c(W, 1) == 4 then return c3(W, 2) end; return c3(W, 1)
  end; local cd, ce = {}, {}
  do
    local cf = 0; for Z = 35, 126 do if Z ~= 39 and Z ~= 91 and Z ~= 92 and Z ~= 93 and Z ~= 96 and cf < 85 then
        cd[cf] = b(Z)
        ce[Z] = cf; cf = cf + 1
      end end
  end; local function cg(W)
    local E = #W; local I, ch = {}, 0; local ci = {}
    for t = 1, E, 4 do
      local aD, au, Z, aN = c(W, t, t + 3)
      local S = aN and 4 or Z and 3 or au and 2 or 1; local U = ((aD * 256 + (au or 0)) * 256 + (Z or 0)) * 256 +
      (aN or 0)
      for T = 5, 1, -1 do
        local _ = U % 85; ci[T] = _; U = (U - _) / 85
      end; for T = 1, S + 1 do
        ch = ch + 1; I[ch] = cd[ci[T]]
      end; y = y + 8; if y >= v then F() end
    end; return e(I)
  end; local function cj(W)
    local E = #W; local I, ch = {}, 0; for t = 1, E, 5 do
      local l = E - t + 1; if l > 5 then l = 5 end; if l == 1 then error("corrupt text data", 0) end; local U = 0; for T = 0, 4 do
        local ck = 84; if T < l then
          ck = ce[c(W, t + T)]
          if not ck then error("invalid character in text data", 0) end
        end; U = U * 85 + ck
      end; if l == 5 and U >= 4294967296 then error("corrupt text data", 0) end; local cl = b(a(U / 16777216) % 256,
        a(U / 65536) % 256, a(U / 256) % 256, U % 256)
      ch = ch + 1; I[ch] = l == 5 and cl or d(cl, 1, l - 1)
      y = y + 8; if y >= v then F() end
    end; return e(I)
  end; local function cm(U, c5) return cg(c4(U, c5)) end; local function cn(W) return c8(cj(W)) end; return { encodeText =
  cm, decodeText = cn, toText = cg, fromText = cj, encode = c4, decode = c8, rencode = c9, rdecode = ca, serialize = G, deserialize =
  V, lzCompress = bR, lzDecompress = bz, setLevel = ai, setChunkSize = ak, encodeChunked = cb, decodeChunked = cc }
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
  fl.write(lib.compressor.rencode(d, 3)) -- Compress it 3 times for maximum saves
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
  return lib.compressor.rdecode(readFile(path), 3)
end

local function readCompFileT(path)
  return textutils.unserialise(readCompFile(path))
end

lib.compressor = buildCompressor() -- compressor.encode, compressor.decode
lib.sha256 = buildHasher()

local parts = {} -- Partition Data
local heir = {}  -- Filesystem Heirarchy

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
    r[#r + 1] = fs.getName(npath)
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
  if type(r) == "table" then
    return r[nm]
  end
end

local function pathExists(path)
  local p = getPath(path)
  return type(p) ~= "nil"
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

local function writePath(path, data)
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

local function setPath(path, data)
  -- Only meant to change disk partition block heirs, not the disk partitions
  -- Made to overwrite
  path = fs.combine(path) -- Sanitize to Absolute Path
  local p = getPath(fs.getDir(path))
  if isPartition(path) or type(p) ~= "table" then
    return false
  else
    local nm = fs.getName(path)
    p[nm] = data
    return true
  end
end

function lib.buildPartition(dir, name)
  -- Sets up a new hvfs partition directory
  assert(not fs.exists(dir), "Trying to build new partition on existing path")

  fs.makeDir(dir)
  writeFile(fs.combine(dir, ".hvfs"), {
    vers = lib.version,
    name = tostring(name or fs.getName(dir))
  })                                          -- Metadata
  writeCompFile(fs.combine(dir, ".heir"), {}) -- FS Heirarchy
  fs.makeDir(fs.combine(dir, ".blks"))        -- Compressed Blocks
end

function lib.isHVFS(dir)
  return fs.exists(fs.combine(dir, ".hvfs")) and fs.exists(fs.combine(dir, ".heir")) and fs.exists(fs.combine(dir, ".blks"))
end

function lib.getHVFSMeta(dir)
  return readFileT(fs.combine(dir,".hvfs"))
end

function lib.mountPartition(dir, name)
  -- Add FileSystem Heirarchy to Heirarchy
  assert(lib.isHVFS(dir), "Directory is not an HVFS partition")
  if type(name) == "string" then
    assert(not heir[name], "Overlapping mount paths")
  else
    name = readFileT(fs.combine(dir, ".hvfs")).name
    local i = 1
    while heir[name] do
      name = string.format("%s%n", name, i)
      i = i + 1
    end
  end
  heir[name] = readCompFileT(fs.combine(dir, ".heir"))
  parts[name] = {path=dir, meta=lib.getHVFSMeta(dir)}
  return name
end

function lib.unmount(name)
  heir[name] = nil
  parts[name] = nil
end

function lib.updateHeir(name)
  if heir[name] then
    writeCompFile(fs.combine(parts[name].path, ".heir"), heir[name])
  end
end

function lib.getPartitionPath(name)
  return parts[name].path
end

function lib.isDir(path)
  local d = getPath(path)
  return type(d) == "table"
end

function lib.exists(path)
  local d = getPath(path)
  return type(d) ~= "nil"
end

function lib.makeDir(path)
  local suc = writePath(path, {})
  if suc then
    lib.updateHeir(pathPartition(path))
  end
  return suc
end
lib.mkdir = lib.makeDir -- Deprecated but still supported

local function getBlockData(path)
  -- Returns block data
  path = fs.combine(path) -- Sanitize Path
  assert(not isPartition(path), "No block in partition", 0)
  assert(lib.isDir(fs.getDir(path)), "Block must exist in directory", 0)
  local bid = lib.sha256(pathRemoveFirst(path))
  -- Clean Path, Block ID, Block Path
  return path, bid, fs.combine(parts[pathPartition(path)].path, ".blks", bid)
end

local function deleteBlock(path)
  local npath, bid, bpath = getBlockData(path)
  fs.delete(bpath)
end

local function deletePath(path)
  path = fs.combine(path) -- Sanitize to Absolute Path
  local p = getPath(fs.getDir(path))
  if type(p) ~= "table" then
    return false
  else
    local nm = fs.getName(path)
    local d = p[nm]
    if type(d) == "table" then
      for k, _ in pairs(d) do
        deletePath(fs.combine(path, k))
      end
    else
      deleteBlock(path)
    end
    if p ~= heir then
      p[nm] = nil
    end
    return true
  end
end

local function writeBlock(path, data)
  local npath, bid, bpath = getBlockData(path)
  writeCompFile(bpath, data)
end

local function readBlock(path)
  local npath, bid, bpath = getBlockData(path)
  assert(fs.exists(bpath), "Cannot read: Block doesn't exist", 0)
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
    lib.updateHeir(pathPartition(path))
  end
  return suc
end

local function referenceBlock(path, opath)
  -- Create a reference to a Block (Also supports linking other blocks)
  local npath, bid, bpath = getBlockData(opath)
  return setPath(path, bid)
end

function lib.open(path, mode)
  assert(not isPartition(path), "Cannot open a partition as file data", 0)
  assert(lib.isDir(fs.getDir(path)), "Trying to open file in directory that doesn't exist", 0)
  local dir = getPath(fs.getDir(path))
  local pt = pathPartition(path)
  local handle = {}

  if mode == "w+" or mode == "w" then
    -- Create fresh block
    writeBlock(path, "")
    assert(referenceBlock(path, path), "File open: Failed to reserve block")
  else
    -- If not, assert the path exists
    assert(existsBlock(path), "Cannot open, file doesn't exist")
  end

  if mode == "r+" or mode == "r" or mode == "w+" then
    function handle.readAll()
      return readBlock(path)
    end
  end

  if mode == "r+" or mode == "w" or mode == "w+" then
    function handle.write(data)
      writeBlock(path, tostring(data))
    end
  end

  function handle.close()
    lib.updateHeir(pt)
    handle = nil
  end

  return handle
end

function lib.list(path, abs)
  path = fs.combine(path or ".")
  local dir = getPath(path)
  if type(dir) == "table" then
    local ht = tableKeys(dir)
    table.sort(ht)
    if abs then
      ht = tableMap(ht, function(p)
        return fs.combine(path, p)
      end)
    end
    return ht
  end
end

function lib.fix(path)
  -- Fix File System (Clear out Zombie Blocks, remove broken paths)
  local suc, res = pcall(function()
    return lib.mountPartition(path)
  end)
  if not suc then
    -- Unsaveable loss, try to recover metadata and clean it out
    if lib.isHVFS(path) then
      local meta = lib.getHVFSMeta(path)
      fs.delete(path)
      lib.buildPartition(path,meta.name)
      return "Gutted Unsaveable Partition"
    end
    return "Missing Meta Data (Cannot Restore Partition)"
  end
  local mpath = res

  local areg = tableFlip(fs.list(fs.combine(parts[mpath].path,".blks")))
  local kreg = tableMap(areg, function(x) return x; end) -- Just copy the registry
  local dpaths = 0

  local function checkDir(dir)
    for k, v in pairs(dir) do
      if type(v) == "table" then
        checkDir(v)
      else
        if areg[v] then
          -- Block exists for this path, remove from kill registry
          kreg[v] = nil
        else
          -- Block doesn't exist for this path, kill it
          dir[k] = nil
          dpaths = dpaths + 1
        end
      end
    end
  end
  checkDir(heir[mpath])

  for _, x in ipairs(kreg) do fs.delete(fs.combine(parts[mpath].path,".blks",x)) end -- Kill registry clear
  
  lib.updateHeir(mpath)
  lib.unmount(mpath)
  return string.format("Cleared %s Zombies,  Removed %s Dead Files",#kreg,dpaths)
end

lib.fs = {} -- Library for interacting with the builtin FS

function lib.fs.clone(path, opath)
  -- Clones path from FS and puts it into HVFS
  path, opath = fs.combine(path), fs.combine(opath) -- Sanitize paths
  assert(fs.exists(path), "Cannot clone path, doesn't exist")
  assert(getPath(opath) ~= heir, "Cannot edit directly on the heirarchy, must choose partition")
  local pdir = path
  if parts[pathPartition(opath)].path == pdir or pdir == "rom" then
    -- Dismiss directly copying these directories (Rom & Current Partition Data)
    return false
  end
  lib.delete(opath)
  if fs.isDir(path) then
    lib.mkdir(opath)
    for _, k in ipairs(fs.list(path)) do
      lib.fs.clone(fs.combine(path, k), fs.combine(opath, k))
      sleep(0) -- Yield
    end
  else
    local fl = lib.open(opath, "w")
    fl.write(readFile(path))
    fl.close()
  end
end

function lib.fs.grab(path, opath)
  -- Grabs path from HVFS and puts it into FS
  path, opath = fs.combine(path), fs.combine(opath) -- Sanitize paths
  assert(lib.exists(path), "Cannot grab path, doesn't exist")
  fs.delete(opath)
  if lib.isDir(path) then
    fs.mkdir(opath)
    for _, k in ipairs(lib.list(path)) do
      lib.fs.grab(fs.combine(path, k), fs.combine(opath, k))
      sleep(0) -- Yield
    end
  else
    local fl = lib.open(path, "r")
    writeFile(opath, fl.readAll())
    fl.close()
  end
  return true
end

if not isRequired() then
  local c = args[1]

  if c == "build" then
    lib.buildPartition(fs.combine(shell.resolve("."), args[2]), args[3])
    print(string.format("Built Partition '%s' in '%s'", args[3] or args[2], fs.combine(shell.resolve("."), args[2])))
  elseif c == "clear" then
    lib.mountPartition(fs.combine(shell.resolve("."), args[2]), "a")
    lib.delete("a")
    print(string.format("[%s] Cleared Partition", args[2]))
  elseif c == "rm" then
    lib.mountPartition(fs.combine(shell.resolve("."), args[2]), "a")
    lib.delete(fs.combine("a", args[3]))
    print(string.format("[%s] Removed path '%s'", args[2], args[3]))
  elseif c == "mkdir" then
    lib.mountPartition(fs.combine(shell.resolve("."), args[2]), "a")
    lib.mkdir(fs.combine("a", args[3]))
    print(string.format("[%s] Created dir '%s'", args[2], args[3]))
  elseif c == "ls" then
    lib.mountPartition(fs.combine(shell.resolve("."), args[2]), "temp")
    print(table.concat(lib.list(fs.combine("temp", args[3] or ".")), " "))
  elseif c == "fix" then
    local rs = lib.fix(fs.combine(shell.resolve("."),args[2]))
    print(string.format("[%s] Fixed Partition Successfully: %s", args[2],rs))
  elseif c == "cat" then
    lib.mountPartition(fs.combine(shell.resolve("."), args[2]), "temp")
    local fl = lib.open(fs.combine("temp", args[3]), "r")
    print(fl.readAll())
    fl.close()
  elseif c == "grab" then
    lib.mountPartition(fs.combine(shell.resolve("."), args[2]), "temp")
    local ipath, opath = fs.combine("temp", args[3]), fs.combine(shell.resolve("."), args[4])
    local fl = lib.fs.grab(ipath, opath)
    print(string.format("[%s] Grabbed File from HVFS '%s' into FS '%s'", args[2], args[3], args[4]))
  elseif c == "clone" then
    lib.mountPartition(fs.combine(shell.resolve("."), args[3]), "temp")
    local ipath, opath = fs.combine(shell.resolve("."), args[2]), fs.combine("temp", args[4])
    local fl = lib.fs.clone(ipath, opath)
    print(string.format("[%s] Cloned File from FS '%s' into HVFS '%s'", args[3], args[2], args[4]))
  else
    error(string.format("Unrecognized HVFS Command: '%s'", c), 0)
  end
end

return lib
