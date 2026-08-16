/**
 * RobloxVMObf :: Anti-Tamper Generator
 * Linked to VM state. If any check fails -> loop 100M
 */

const { randStr, randHex, randInt, generateDeadCodeBlock } = require("./crypto-utils");

function generateAntiTamperModule(vmTableVar, envVar) {
  const AT   = randStr(5);  // anti-tamper function name
  const DBG  = randStr(4);  // debug local
  const INF  = randStr(4);  // info local
  const CHK  = randStr(5);  // checksum local
  const I    = randStr(3);  // loop var
  const T1   = randStr(3);  // temp
  const T2   = randStr(3);  // temp
  const MT   = randStr(3);  // metatable local
  const G    = randStr(4);  // _G local
  const CL   = randStr(4);  // clock local
  const SEED = randHex(4);  // integrity seed

  const checks = [];

  // Check 1: debug hook detection
  checks.push(`
    local ${DBG}=debug or _G.debug or (getfenv and getfenv(0).debug);
    if ${DBG} and ${DBG}.getinfo then
      local ${INF}=${DBG}.getinfo(3);
      if ${INF} and (${INF}.what=="C" or ${INF}.namewhat=="hook") then
        for ${I}=1,100000000 do end
        return error("AT:01")
      end
    end
  `);

  // Check 2: environment integrity
  checks.push(`
    local ${G}=_G or (getfenv and getfenv(0)) or {};
    if rawget(${G},"${randStr(8)}")~=nil then
      for ${I}=1,100000000 do end
      return error("AT:02")
    end
  `);

  // Check 3: VM metatable must exist and be locked
  checks.push(`
    local ${MT}=getmetatable(${vmTableVar});
    if ${MT}==nil then
      for ${I}=1,100000000 do end
      return error("AT:03")
    end
    if rawget(${MT},"__metatable")~=false then
      for ${I}=1,100000000 do end
      return error("AT:04")
    end
  `);

  // Check 4: string.dump detection (attempt to decompile)
  checks.push(`
    local ${T1}=string.dump;
    if ${T1} then
      local ${T2},${CL}=pcall(${T1},function() end);
      if ${CL} and type(${CL})=="string" and #${CL}>0 then
        -- dump available, mark as suspicious
        local ${CHK}=0;
        for ${I}=1,100000000 do ${CHK}=(${CHK}+1)%0x10000; end
        return error("AT:05")
      end
    end
  `);

  // Check 5: timing attack (anti-debug with clock)
  checks.push(`
    local ${CL}=os and os.clock or tick;
    if ${CL} then
      local ${T1}=${CL}();
      local ${T2}=0;
      for ${I}=1,5000 do ${T2}=(${T2}+${I}*3)%0x7FFFFFFF; end
      local ${CHK}=${CL}();
      if (${CHK}-${T1})>0.5 then
        for ${I}=1,100000000 do end
        return error("AT:06")
      end
    end
  `);

  // Check 6: instruction counter / trace (simple entropy check)
  checks.push(`
    local ${T1}=0; local ${T2}=0;
    for ${I}=1,50 do ${T1}=(${T1}+${I}*7)%0xFFFFFF; ${T2}=(${T2}+${T1}*13)%0xFFFFFF; end
    if ${T1}~=${randHex(6)} and ${T2}~=${randHex(6)} then
      -- values should match precomputed if not tampered (dummy check that always passes normally)
    end
  `);

  // Shuffle checks
  for (let i = checks.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [checks[i], checks[j]] = [checks[j], checks[i]];
  }

  const body = checks.join("\n");

  return {
    functionName: AT,
    code: `
local ${AT}=function(${envVar})
  ${body}
  return true
end
`,
    call: `${AT}(${envVar})`
  };
}

function generateMetatableShield(vmTableVar, atFuncName) {
  const IDX = randStr(5);
  const NWI = randStr(5);
  const I = randStr(3);
  return `
setmetatable(${vmTableVar},{
  __index=function(t,k)
    if not ${atFuncName}(${vmTableVar}) then
      for ${I}=1,100000000 do end
      return error("MT:idx")
    end
    return rawget(t,k)
  end,
  __newindex=function(t,k,v)
    if not ${atFuncName}(${vmTableVar}) then
      for ${I}=1,100000000 do end
      return error("MT:nwi")
    end
    return rawset(t,k,v)
  end,
  __metatable=false,
  __tostring=function()
    for ${I}=1,100000000 do end
    return error("MT:str")
  end,
  __len=function()
    for ${I}=1,100000000 do end
    return error("MT:len")
  end
})
`;
}

module.exports = { generateAntiTamperModule, generateMetatableShield };
