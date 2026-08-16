/**
 * RobloxVMObf :: Crypto & Randomization Utilities
 * Multi-layer XOR, string table fragmentation, identifier mangling
 */

const crypto = require("crypto");

const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_";
const HEXC  = "0123456789ABCDEF";

function randStr(len) {
  let s = "";
  for (let i = 0; i < len; i++) s += CHARS[Math.floor(Math.random() * CHARS.length)];
  return s;
}

function randHex(len) {
  let s = "0x";
  for (let i = 0; i < len; i++) s += HEXC[Math.floor(Math.random() * 16)];
  return s;
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function xorEncrypt(buf, key) {
  const out = [];
  for (let i = 0; i < buf.length; i++) {
    const k = ((key >>> 0) + (i * 0x9E3779B9 >>> 0)) & 0xFF;
    out.push(buf[i] ^ k);
  }
  return out;
}

function xorEncryptLayered(buf, keys) {
  let cur = Buffer.from(buf);
  for (const k of keys) {
    const arr = [];
    for (let i = 0; i < cur.length; i++) {
      const mix = ((k >>> 0) + (i * 0x6C078965 >>> 0) + (i * i)) & 0xFF;
      arr.push(cur[i] ^ mix);
    }
    cur = Buffer.from(arr);
  }
  return [...cur];
}

function generateStringTable(strings) {
  const keys = [randInt(0x11, 0xFE), randInt(0x11, 0xFE), randInt(0x11, 0xFE)];
  const entries = strings.map((str, idx) => {
    const bytes = Buffer.from(str, "utf8");
    const encrypted = xorEncryptLayered(bytes, keys);
    const id = randHex(4);
    return { id, idx, encrypted, len: str.length };
  });
  return { keys, entries };
}

function generateIdentifierPool(count) {
  const pool = [];
  const seen = new Set();
  while (pool.length < count) {
    const id = randStr(randInt(3, 7));
    if (!seen.has(id)) { seen.add(id); pool.push(id); }
  }
  return pool;
}

function generateHexConstants(count) {
  const arr = [];
  for (let i = 0; i < count; i++) arr.push(randHex(randInt(3, 6)));
  return arr;
}

function generateDummyMath() {
  const a = randStr(3), b = randStr(3), c = randStr(3), d = randStr(3);
  const v1 = randHex(4), v2 = randHex(4), v3 = randHex(4), v4 = randHex(4), v5 = randHex(4);
  return `local function ${a}(${b}) local ${c}=((((${v1})-(${v2}))*${v3})+${v4})%${v5}; local ${d}=math.floor(${c}/(${randHex(2)}+1)); return ${d} end`;
}

function generateDeadCodeBlock(depth = 3) {
  if (depth <= 0) return generateDummyMath();
  const type = randInt(0, 3);
  if (type === 0) {
    const v = randStr(3), cond = randHex(2);
    return `if ${cond}>${randHex(2)} then local ${v}=${randHex(4)}; return ${v} end; ` + generateDeadCodeBlock(depth - 1);
  } else if (type === 1) {
    const v = randStr(3), lim = randInt(3, 8);
    let s = `for ${v}=1,${lim} do `;
    s += generateDeadCodeBlock(depth - 1);
    s += ` end; `;
    return s + generateDeadCodeBlock(depth - 1);
  } else {
    return generateDummyMath() + "; " + generateDeadCodeBlock(depth - 1);
  }
}

module.exports = {
  randStr, randHex, randInt,
  xorEncrypt, xorEncryptLayered,
  generateStringTable, generateIdentifierPool,
  generateHexConstants, generateDummyMath, generateDeadCodeBlock
};
