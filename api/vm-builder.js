/**
 * RobloxVMObf :: VM Builder
 * Generates a stack-based VM runtime in Lua with custom bytecode
 */

const { randStr, randHex, randInt, xorEncrypt, generateIdentifierPool } = require("./crypto-utils");

const OPCODES = [
  { name:"NOP",  args:0 },
  { name:"LOAD", args:2 },   // LOAD reg, constIdx
  { name:"MOVE", args:2 },   // MOVE dst, src
  { name:"PUSH", args:1 },   // PUSH reg
  { name:"POP",  args:1 },   // POP reg
  { name:"ADD",  args:3 },   // ADD dst, left, right
  { name:"SUB",  args:3 },
  { name:"MUL",  args:3 },
  { name:"DIV",  args:3 },
  { name:"POW",  args:3 },
  { name:"MOD",  args:3 },
  { name:"XOR",  args:3 },
  { name:"NOT",  args:2 },
  { name:"LEN",  args:2 },
  { name:"CONCAT",args:3 },
  { name:"EQ",   args:3 },   // EQ dst, left, right
  { name:"LT",   args:3 },
  { name:"GT",   args:3 },
  { name:"JMP",  args:1 },   // JMP offset
  { name:"JZ",   args:2 },   // JZ reg, offset
  { name:"JNZ",  args:2 },   // JNZ reg, offset
  { name:"GETTABLE", args:3 },
  { name:"SETTABLE", args:3 },
  { name:"GETGLOBAL",args:2 },
  { name:"SETGLOBAL",args:2 },
  { name:"NEWTABLE", args:2 },
  { name:"CALL", args:2 },   // CALL reg, nresults
  { name:"RETURN", args:1 },
  { name:"CLOSURE",args:2 },
  { name:"VARARG", args:1 },
  { name:"LOADK",  args:2 }, // LOADK reg, value (inline)
  { name:"SELF",   args:2 },
];

function buildVMRuntime(vmName, atFuncName, stringTableVar, decryptFuncName) {
  const R = randStr(3);   // registers
  const S = randStr(3);   // stack
  const PC = randStr(3);  // program counter
  const BC = randStr(3);  // bytecode
  const CN = randStr(3);  // constants
  const UP = randStr(3);  // upvalues
  const ENV = randStr(4); // environment
  const I = randStr(3);   // loop index
  const OP = randStr(3);  // opcode
  const A = randStr(3);   // arg A
  const B = randStr(3);   // arg B
  const C = randStr(3);   // arg C
  const T = randStr(3);   // temp
  const T2 = randStr(3);  // temp2
  const RES = randStr(4); // result

  const opMap = {};
  OPCODES.forEach((op, idx) => {
    opMap[op.name] = randHex(2); // random opcode ids
  });

  let dispatcher = "";
  OPCODES.forEach(op => {
    const oid = opMap[op.name];
    let caseBody = "";
    switch (op.name) {
      case "NOP":
        caseBody = `break`;
        break;
      case "LOAD":
        caseBody = `${R}[${A}]=${CN}[${B}]; break`;
        break;
      case "MOVE":
        caseBody = `${R}[${A}]=${R}[${B}]; break`;
        break;
      case "PUSH":
        caseBody = `table.insert(${S},${R}[${A}]); break`;
        break;
      case "POP":
        caseBody = `${R}[${A}]=table.remove(${S}); break`;
        break;
      case "ADD":
        caseBody = `${R}[${A}]=${R}[${B}]+${R}[${C}]; break`;
        break;
      case "SUB":
        caseBody = `${R}[${A}]=${R}[${B}]-${R}[${C}]; break`;
        break;
      case "MUL":
        caseBody = `${R}[${A}]=${R}[${B}]*${R}[${C}]; break`;
        break;
      case "DIV":
        caseBody = `${R}[${A}]=${R}[${B}]/${R}[${C}]; break`;
        break;
      case "POW":
        caseBody = `${R}[${A}]=${R}[${B}]^${R}[${C}]; break`;
        break;
      case "MOD":
        caseBody = `${R}[${A}]=${R}[${B}]%${R}[${C}]; break`;
        break;
      case "XOR":
        caseBody = `${R}[${A}]=bit32.bxor(${R}[${B}],${R}[${C}]); break`;
        break;
      case "NOT":
        caseBody = `${R}[${A}]=not ${R}[${B}]; break`;
        break;
      case "LEN":
        caseBody = `${R}[${A}]=#${R}[${B}]; break`;
        break;
      case "CONCAT":
        caseBody = `${R}[${A}]=tostring(${R}[${B}])..tostring(${R}[${C}]); break`;
        break;
      case "EQ":
        caseBody = `${R}[${A}]=(${R}[${B}]==${R}[${C}]); break`;
        break;
      case "LT":
        caseBody = `${R}[${A}]=(${R}[${B}]<${R}[${C}]); break`;
        break;
      case "GT":
        caseBody = `${R}[${A}]=(${R}[${B}]>${R}[${C}]); break`;
        break;
      case "JMP":
        caseBody = `${PC}=${PC}+${A}; break`;
        break;
      case "JZ":
        caseBody = `if not ${R}[${A}] then ${PC}=${PC}+${B} end; break`;
        break;
      case "JNZ":
        caseBody = `if ${R}[${A}] then ${PC}=${PC}+${B} end; break`;
        break;
      case "GETTABLE":
        caseBody = `${R}[${A}]=${R}[${B}][${R}[${C}]]; break`;
        break;
      case "SETTABLE":
        caseBody = `${R}[${B}][${R}[${C}]]=${R}[${A}]; break`;
        break;
      case "GETGLOBAL":
        caseBody = `${R}[${A}]=${ENV}[${CN}[${B}]]; break`;
        break;
      case "SETGLOBAL":
        caseBody = `${ENV}[${CN}[${B}]]=${R}[${A}]; break`;
        break;
      case "NEWTABLE":
        caseBody = `${R}[${A}]={}; for ${I}=1,${B} do table.insert(${R}[${A}],nil) end; break`;
        break;
      case "CALL":
        caseBody = `${T}=${R}[${A}]; ${RES}={${T}(unpack(${S},1,${B} or 0))}; ${S}={}; for ${I}=1,#${RES} do ${R}[${I}-1]=${RES}[${I}] end; break`;
        break;
      case "RETURN":
        caseBody = `return unpack(${R},1,${A} or 0)`;
        break;
      case "CLOSURE":
        caseBody = `${R}[${A}]=function(...) return ${vmName}(${B},{...}) end; break`;
        break;
      case "VARARG":
        caseBody = `for ${I}=1,${A} do ${R}[${I}-1]=arg[${I}] end; break`;
        break;
      case "LOADK":
        caseBody = `${R}[${A}]=${B}; break`;
        break;
      case "SELF":
        caseBody = `${R}[${A}+1]=${R}[${B}]; ${R}[${A}]=${R}[${B}][${CN}[${C}]]; break`;
        break;
      default:
        caseBody = `break`;
    }
    dispatcher += `    [${oid}]=function(${A},${B},${C}) ${caseBody} end,\n`;
  });

  const runtime = `
local function ${vmName}(${BC},${ENV})
  local ${R}={};
  local ${S}={};
  local ${PC}=1;
  local ${CN}=${BC}.k or {};
  local ${UP}=${BC}.u or {};
  local ${OP}=${BC}.o or {};
  local ${T}=${BC}.t or {};

  -- Anti-tamper hook on entry
  if not ${atFuncName}(${ENV}) then
    local ${I}=0;
    for ${I}=1,100000000 do end
    return error("VM:AT")
  end

  while ${PC}<=#${OP} do
    local ${T2}=${OP}[${PC}];
    local ${A},${B},${C}=${T2}[1],${T2}[2],${T2}[3];
    local ${T}=${T}[${T2}[4] or ${randHex(2)}];
    if ${T} then
      ${T}(${A},${B},${C});
    else
      ${PC}=${PC}+1;
    end
    ${PC}=${PC}+1;
  end

  return unpack(${R},1,${BC}.n or 0);
end
`;

  return { runtime, opMap, vmName };
}

function compileToBytecode(source, opMap, stringTable) {
  // Simplified compiler: we tokenize loosely and emit custom bytecode
  // For a real obfuscator this would be a full parser; here we generate
  // a plausible bytecode block that loads and executes the source string
  const ops = [];
  const consts = [];

  // Add encrypted source as constant 0
  consts.push(stringTable.entries[0] ? stringTable.entries[0].id : "\"\"");

  // LOAD encrypted source into reg 0
  ops.push([opMap["LOAD"], 0, 0, randHex(2)]);

  // GETGLOBAL decrypt function into reg 1
  ops.push([opMap["GETGLOBAL"], 1, 1, randHex(2)]);

  // PUSH reg 0 (source)
  ops.push([opMap["PUSH"], 0, 0, randHex(2)]);

  // CALL reg 1, 1 result
  ops.push([opMap["CALL"], 1, 1, randHex(2)]);

  // MOVE result to reg 0
  ops.push([opMap["MOVE"], 0, 1, randHex(2)]);

  // GETGLOBAL load/loadstring into reg 1
  ops.push([opMap["GETGLOBAL"], 1, 2, randHex(2)]);

  // PUSH reg 0 (decrypted source)
  ops.push([opMap["PUSH"], 0, 0, randHex(2)]);

  // CALL reg 1, 1 result (get compiled function)
  ops.push([opMap["CALL"], 1, 1, randHex(2)]);

  // CALL compiled function, 0 results (execute)
  ops.push([opMap["CALL"], 1, 0, randHex(2)]);

  // RETURN
  ops.push([opMap["RETURN"], 0, 0, randHex(2)]);

  return { ops, consts };
}

module.exports = { buildVMRuntime, compileToBytecode, OPCODES };
