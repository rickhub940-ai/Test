--[[
  RobloxVMObf :: VM Runtime Module
  Standalone VM that can execute custom bytecode inside Roblox
  with built-in anti-tamper hooks.
--]]

local VMRuntime = {}
VMRuntime.__index = VMRuntime

-- Opcode table (will be randomized by obfuscator)
local OPCODES = {
	NOP    = 0x00,
	LOAD   = 0x01,
	MOVE   = 0x02,
	PUSH   = 0x03,
	POP    = 0x04,
	ADD    = 0x05,
	SUB    = 0x06,
	MUL    = 0x07,
	DIV    = 0x08,
	POW    = 0x09,
	MOD    = 0x0A,
	XOR    = 0x0B,
	NOT    = 0x0C,
	LEN    = 0x0D,
	CONCAT = 0x0E,
	EQ     = 0x0F,
	LT     = 0x10,
	GT     = 0x11,
	JMP    = 0x12,
	JZ     = 0x13,
	JNZ    = 0x14,
	GETTABLE  = 0x15,
	SETTABLE  = 0x16,
	GETGLOBAL = 0x17,
	SETGLOBAL = 0x18,
	NEWTABLE  = 0x19,
	CALL      = 0x1A,
	RETURN    = 0x1B,
	CLOSURE   = 0x1C,
	VARARG    = 0x1D,
	LOADK     = 0x1E,
	SELF      = 0x1F,
}

function VMRuntime.new(antiTamperFunc)
	local self = setmetatable({}, VMRuntime)
	self.AT = antiTamperFunc or function() return true end
	self.Registers = {}
	self.Stack = {}
	self.PC = 1
	self.Constants = {}
	self.Upvalues = {}
	self.Bytecode = {}
	self.Environment = getfenv and getfenv(0) or _G
	return self
end

function VMRuntime:CheckTamper()
	if not self.AT(self.Environment) then
		local i = 0
		for i = 1, 100000000 do end
		error("VMRuntime: Anti-Tamper failed")
	end
end

function VMRuntime:LoadBytecode(bc)
	self:CheckTamper()
	self.Bytecode = bc.o or {}
	self.Constants = bc.k or {}
	self.Upvalues = bc.u or {}
	self.PC = 1
	self.Registers = {}
	self.Stack = {}
end

function VMRuntime:Execute()
	self:CheckTamper()

	local bit32 = bit32 or _G.bit32 or {
		bxor = function(a, b)
			local r, p = 0, 1
			while a > 0 or b > 0 do
				local A, B = a % 2, b % 2
				if A ~= B then r = r + p end
				a, b, p = math.floor(a / 2), math.floor(b / 2), p * 2
			end
			return r
		end,
		band = function(a, b)
			local r, p = 0, 1
			while a > 0 or b > 0 do
				local A, B = a % 2, b % 2
				if A == 1 and B == 1 then r = r + p end
				a, b, p = math.floor(a / 2), math.floor(b / 2), p * 2
			end
			return r
		end,
		bnot = function(x) return (-1 - x) % 0x100000000 end,
	}

	while self.PC <= #self.Bytecode do
		self:CheckTamper()

		local inst = self.Bytecode[self.PC]
		local op = inst[1]
		local A = inst[2]
		local B = inst[3]
		local C = inst[4]

		if op == OPCODES.NOP then
			-- nothing

		elseif op == OPCODES.LOAD then
			self.Registers[A] = self.Constants[B]

		elseif op == OPCODES.MOVE then
			self.Registers[A] = self.Registers[B]

		elseif op == OPCODES.PUSH then
			table.insert(self.Stack, self.Registers[A])

		elseif op == OPCODES.POP then
			self.Registers[A] = table.remove(self.Stack)

		elseif op == OPCODES.ADD then
			self.Registers[A] = self.Registers[B] + self.Registers[C]

		elseif op == OPCODES.SUB then
			self.Registers[A] = self.Registers[B] - self.Registers[C]

		elseif op == OPCODES.MUL then
			self.Registers[A] = self.Registers[B] * self.Registers[C]

		elseif op == OPCODES.DIV then
			self.Registers[A] = self.Registers[B] / self.Registers[C]

		elseif op == OPCODES.POW then
			self.Registers[A] = self.Registers[B] ^ self.Registers[C]

		elseif op == OPCODES.MOD then
			self.Registers[A] = self.Registers[B] % self.Registers[C]

		elseif op == OPCODES.XOR then
			self.Registers[A] = bit32.bxor(self.Registers[B], self.Registers[C])

		elseif op == OPCODES.NOT then
			self.Registers[A] = not self.Registers[B]

		elseif op == OPCODES.LEN then
			self.Registers[A] = #self.Registers[B]

		elseif op == OPCODES.CONCAT then
			self.Registers[A] = tostring(self.Registers[B]) .. tostring(self.Registers[C])

		elseif op == OPCODES.EQ then
			self.Registers[A] = (self.Registers[B] == self.Registers[C])

		elseif op == OPCODES.LT then
			self.Registers[A] = (self.Registers[B] < self.Registers[C])

		elseif op == OPCODES.GT then
			self.Registers[A] = (self.Registers[B] > self.Registers[C])

		elseif op == OPCODES.JMP then
			self.PC = self.PC + A

		elseif op == OPCODES.JZ then
			if not self.Registers[A] then
				self.PC = self.PC + B
			end

		elseif op == OPCODES.JNZ then
			if self.Registers[A] then
				self.PC = self.PC + B
			end

		elseif op == OPCODES.GETTABLE then
			self.Registers[A] = self.Registers[B][self.Registers[C]]

		elseif op == OPCODES.SETTABLE then
			self.Registers[B][self.Registers[C]] = self.Registers[A]

		elseif op == OPCODES.GETGLOBAL then
			self.Registers[A] = self.Environment[self.Constants[B]]

		elseif op == OPCODES.SETGLOBAL then
			self.Environment[self.Constants[B]] = self.Registers[A]

		elseif op == OPCODES.NEWTABLE then
			self.Registers[A] = {}
			for i = 1, B do
				table.insert(self.Registers[A], nil)
			end

		elseif op == OPCODES.CALL then
			local fn = self.Registers[A]
			local args = {}
			for i = 1, #self.Stack do
				args[i] = self.Stack[i]
			end
			self.Stack = {}
			local results = {fn(unpack(args))}
			for i = 1, #results do
				self.Registers[i - 1] = results[i]
			end

		elseif op == OPCODES.RETURN then
			local ret = {}
			for i = 1, A do
				ret[i] = self.Registers[i - 1]
			end
			return unpack(ret)

		elseif op == OPCODES.CLOSURE then
			self.Registers[A] = function(...)
				return self:ExecuteClosure(B, {...})
			end

		elseif op == OPCODES.VARARG then
			-- handled by caller

		elseif op == OPCODES.LOADK then
			self.Registers[A] = B

		elseif op == OPCODES.SELF then
			self.Registers[A + 1] = self.Registers[B]
			self.Registers[A] = self.Registers[B][self.Constants[C]]

		else
			error("VMRuntime: Unknown opcode " .. tostring(op))
		end

		self.PC = self.PC + 1
	end

	return nil
end

function VMRuntime:ExecuteClosure(closureId, args)
	self:CheckTamper()
	-- Simplified: in full implementation would switch bytecode context
	return self:Execute()
end

return VMRuntime
