/**
 * RobloxVMObf :: Main API Endpoint
 * POST /api/obfuscate  { "code": "..." }
 * Returns fully obfuscated Lua with VM + Anti-Tamper + Return-End coating
 */

const { randStr, randHex, randInt, xorEncrypt, xorEncryptLayered, generateStringTable, generateIdentifierPool, generateHexConstants, generateDeadCodeBlock } = require("./crypto-utils");
const { generateAntiTamperModule, generateMetatableShield } = require("./anti-tamper");
const { buildVMRuntime, compileToBytecode } = require("./vm-builder");

function obfuscate(sourceCode) {
  if (!sourceCode || typeof sourceCode !== "string") throw new Error("Invalid source");

  // ---- Phase 1: Random identifiers & constants ----
  const ids = generateIdentifierPool(30);
  const hexs = generateHexConstants(20);

  const W     = ids[0];   // main env table
  const VM    = ids[1];   // VM table
  const AT    = ids[2];   // anti-tamper func (will be replaced by generator)
  const DE    = ids[3];   // decrypt func
  const LD    = ids[4];   // loadstring
  const DA    = ids[5];   // data table
  const ST    = ids[6];   // string table
  const MN    = ids[7];   // main entry key
  const ENV   = ids[8];   // environment var
  const BC    = ids[9];   // bytecode var
  const REG   = ids[10];  // registers
  const STACK = ids[11];  // stack
  const PC    = ids[12];  // program counter
  const I     = ids[13];  // loop index
  const T1    = ids[14];  // temp
  const T2    = ids[15];  // temp2
  const T3    = ids[16];  // temp3
  const K1    = ids[17];  // key1
  const K2    = ids[18];  // key2
  const K3    = ids[19];  // key3

  // ---- Phase 2: Encrypt source code ----
  const srcBytes = Buffer.from(sourceCode, "utf8");
  const encKeys = [randInt(0x11, 0xFE), randInt(0x11, 0xFE), randInt(0x11, 0xFE)];
  const encrypted = xorEncryptLayered(srcBytes, encKeys);
  const dataBlock = "{" + encrypted.map(b => "0x" + b.toString(16).padStart(2, "0")).join(",") + "}";

  // ---- Phase 3: Build string table with fragments ----
  const strings = [
    sourceCode,                                    // [0] encrypted source
    "loadstring",                                  // [1] loadstring name
    "load",                                        // [2] load name
    "bit32",                                       // [3] bit32 name
    "bxor",                                        // [4] bxor name
    "debug",                                       // [5] debug name
    "getinfo",                                     // [6] getinfo name
    "getfenv",                                     // [7] getfenv name
    "setfenv",                                     // [8] setfenv name
    "getmetatable",                                // [9] getmetatable name
    "setmetatable",                                // [10] setmetatable name
    "rawget",                                      // [11] rawget name
    "rawset",                                      // [12] rawset name
    "string",                                      // [13] string name
    "dump",                                        // [14] dump name
    "clock",                                       // [15] clock name
    "tick",                                        // [16] tick name
    "os",                                          // [17] os name
    "math",                                        // [18] math name
    "floor",                                       // [19] floor name
    "table",                                       // [20] table name
    "insert",                                      // [21] insert name
    "remove",                                      // [22] remove name
    "unpack",                                      // [23] unpack name
    "error",                                       // [24] error name
    "type",                                        // [25] type name
    "tonumber",                                    // [26] tonumber name
    "tostring",                                    // [27] tostring name
    "_G",                                          // [28] _G name
    "pcall",                                       // [29] pcall name
  ];
  const strTable = generateStringTable(strings);

  // ---- Phase 4: Build Anti-Tamper ----
  const atModule = generateAntiTamperModule(W, W);
  const atFuncName = atModule.functionName;

  // ---- Phase 5: Build VM Runtime ----
  const vmBuild = buildVMRuntime(VM, atFuncName, strTable, DE);
  const vmRuntime = vmBuild.runtime;
  const opMap = vmBuild.opMap;

  // ---- Phase 6: Compile source to custom bytecode ----
  const bcData = compileToBytecode(sourceCode, opMap, strTable);

  // ---- Phase 7: Generate decrypt function ----
  const decryptFunc = `
local function ${DE}(${W},${DA})
  local ${B}=bit32 or _G.bit32;
  if not ${B} then
    local function bxor(a,b) local r,p=0,1;while a>0 or b>0 do local A,B=a%2,b%2;if A~=B then r=r+p end;a,b,p=math.floor(a/2),math.floor(b/2),p*2 end;return r end
    ${B}={bxor=bxor,band=function(a,b) local r,p=0,1;while a>0 or b>0 do local A,B=a%2,b%2;if A==1 and B==1 then r=r+p end;a,b,p=math.floor(a/2),math.floor(b/2),p*2 end;return r end,bnot=function(x) return (-1-x)%0x100000000 end}
  end
  local k1,k2,k3=${encKeys[0]},${encKeys[1]},${encKeys[2]};
  local ${T1}="";
  for i=1,#${DA} do
    local b=${DA}[i];
    b=${B}.bxor(b,(k3+i)%256);
    b=${B}.bxor(b,(k2+i*0x6C078965)%256);
    b=${B}.bxor(b,(k1+i*i)%256);
    ${T1}=${T1}..string.char(b);
  end
  return ${T1};
end
`;

  // ---- Phase 8: Generate main entry ----
  const mainEntry = `
local function ${MN}(...)
  -- Environment capture
  local ${ENV}=_G or (getfenv and getfenv(0)) or {};
  ${W}=${W} or {};
  ${W}.${ENV}=${ENV};

  -- Anti-tamper check before anything
  if not ${atFuncName}(${W}) then
    local ${I}=0;
    for ${I}=1,100000000 do end
    return error("MAIN:AT")
  end

  -- Decrypt source
  local ${T1}=${DE}(${W},${W}.${DA});

  -- Load function
  local ${T2}=${ENV}.loadstring or ${ENV}.load or loadstring or load;
  if not ${T2} then
    for ${I}=1,100000000 do end
    return error("MAIN:LD")
  end

  local ${T3},${T2}=${ENV}.pcall(${T2},${T1});
  if not ${T3} or type(${T2})~="function" then
    for ${I}=1,100000000 do end
    return error("MAIN:LC")
  end

  -- Execute through VM wrapper (optional layer)
  return ${T2}(...);
end
`;

  // ---- Phase 9: Assemble big table (goofyscator style) ----
  const tableEntries = [];

  // Entry 0: bit32 provider
  tableEntries.push(`["${hexs[0]}"]=(function(${W},${ids[20]},${ids[21]}) local ${B}=bit32 or _G.bit32 or (function() local function bxor(a,b) local r,p=0,1;while a>0 or b>0 do local A,B=a%2,b%2;if A~=B then r=r+p end;a,b,p=math.floor(a/2),math.floor(b/2),p*2 end;return r end; local function band(a,b) local r,p=0,1;while a>0 or b>0 do local A,B=a%2,b%2;if A==1 and B==1 then r=r+p end;a,b,p=math.floor(a/2),math.floor(b/2),p*2 end;return r end; return {bxor=bxor,band=band,bnot=function(x) return (-1-x)%0x100000000 end,lshift=function(x,n) return (x*(2^n))%0x100000000 end,rshift=function(x,n) return math.floor((x%0x100000000)/(2^n)) end}; end)(); ${W}.b=${B}; end)`);

  // Entry 1: string table init
  const stInit = strTable.entries.map(e => `[${e.id}]={${e.encrypted.join(",")}}`).join(",");
  tableEntries.push(`["${hexs[1]}"]=(function(${W},${ids[22]},${ids[23]}) ${W}.${ST}={${stInit}}; ${W}.sk={${strTable.keys.join(",")}}; end)`);

  // Entry 2: anti-tamper module
  tableEntries.push(`["${hexs[2]}"]=(function(${W},${ids[24]},${ids[25]}) ${atModule.code} end)`);

  // Entry 3: VM runtime
  tableEntries.push(`["${hexs[3]}"]=(function(${W},${ids[26]},${ids[27]}) ${vmRuntime} end)`);

  // Entry 4: decrypt function
  tableEntries.push(`["${hexs[4]}"]=(function(${W},${ids[28]},${ids[29]}) ${decryptFunc} end)`);

  // Entry 5: data block
  tableEntries.push(`["${hexs[5]}"]=(function(${W},${ids[20]},${ids[21]}) ${W}.${DA}=${dataBlock}; end)`);

  // Entry 6: metatable shield
  tableEntries.push(`["${hexs[6]}"]=(function(${W},${ids[22]},${ids[23]}) ${generateMetatableShield(W, atFuncName)} end)`);

  // Entry 7: main entry
  tableEntries.push(`["${MN}"]=(function(${W},${ids[24]},${ids[25]}) ${mainEntry} end)`);

  // Entries 8-19: dummy dead code
  for (let i = 7; i < 19; i++) {
    const d1 = randStr(3), d2 = randStr(3), d3 = randStr(3);
    const h1 = randHex(4), h2 = randHex(4), h3 = randHex(4), h4 = randHex(4);
    tableEntries.push(`["${hexs[i]}"]=(function(${W},${d1},${d2}) local ${d3}=((((${h1})-(${h2}))*${h3})+${h4})%0xFFFFD; return ${randInt(0,999)}; end)`);
  }

  // Shuffle entries
  for (let i = tableEntries.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [tableEntries[i], tableEntries[j]] = [tableEntries[j], tableEntries[i]];
  }

  // ---- Phase 10: Final coating (return ({...})["key"](...)) ----
  const output = `return ({${tableEntries.join(",\n")}})["${MN}"](...)`;

  return output;
}

module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") { res.status(200).end(); return; }
  if (req.method !== "POST") { res.status(405).json({error:"Method Not Allowed"}); return; }

  const body = req.body || {};
  const code = body.code || body.source;
  if (!code || typeof code !== "string") {
    res.status(400).json({error:"Missing 'code' string in JSON body"});
    return;
  }

  try {
    const result = obfuscate(code);
    res.status(200).json({result, ok:true, version:"2.0.0"});
  } catch (err) {
    res.status(500).json({error:err.message, ok:false});
  }
};
