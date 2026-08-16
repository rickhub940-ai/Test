--[[
  RobloxVMObf :: Anti-Tamper Module
  Can be injected into any Lua environment
  Usage: local AT = require(path.to.anti-tamper)
  AT:Protect(vmTable)
--]]

local AntiTamper = {}
AntiTamper.__index = AntiTamper

function AntiTamper.new()
	local self = setmetatable({}, AntiTamper)
	self.Checks = {}
	self.Seed = tick() * 1000 % 0x7FFFFFFF
	self.FailCount = 0
	return self
end

function AntiTamper:GenerateSeed()
	self.Seed = (self.Seed * 0xF83F + tick() * 1000) % 0x7FFFFFFF
	return self.Seed
end

function AntiTamper:AddCheck(name, func)
	self.Checks[name] = func
	return self
end

function AntiTamper:RunChecks(env)
	local passed = 0
	local total = 0

	for name, check in pairs(self.Checks) do
		total = total + 1
		local ok, result = pcall(check, env)
		if ok and result == true then
			passed = passed + 1
		else
			self.FailCount = self.FailCount + 1
			if self.FailCount >= 3 then
				self:Bomb()
			end
			return false, name
		end
	end

	return true, passed .. "/" .. total
end

function AntiTamper:Bomb()
	local i = 0
	for i = 1, 100000000 do
		i = (i + 1) % 0x10000
	end
	error("AntiTamper: Integrity violation detected")
end

function AntiTamper:Protect(vmTable)
	local selfRef = self
	setmetatable(vmTable, {
		__index = function(t, k)
			local ok = selfRef:RunChecks(getfenv and getfenv(0) or _G)
			if not ok then
				selfRef:Bomb()
			end
			return rawget(t, k)
		end,
		__newindex = function(t, k, v)
			local ok = selfRef:RunChecks(getfenv and getfenv(0) or _G)
			if not ok then
				selfRef:Bomb()
			end
			return rawset(t, k, v)
		end,
		__metatable = false,
		__tostring = function()
			selfRef:Bomb()
			return ""
		end,
		__len = function()
			selfRef:Bomb()
			return 0
		end,
	})
	return self
end

-- Built-in checks
function AntiTamper:InstallDefaultChecks()
	-- Check 1: Debug hook detection
	self:AddCheck("debug", function(env)
		local dbg = debug or env.debug or (getfenv and getfenv(0).debug)
		if dbg and dbg.getinfo then
			local info = dbg.getinfo(3)
			if info and (info.what == "C" or info.namewhat == "hook") then
				return false
			end
		end
		return true
	end)

	-- Check 2: Environment integrity
	self:AddCheck("env", function(env)
		local g = _G or (getfenv and getfenv(0)) or {}
		if rawget(g, "__roblox_vm_obf_tampered__") ~= nil then
			return false
		end
		return true
	end)

	-- Check 3: Metatable integrity
	self:AddCheck("meta", function(env)
		local mt = getmetatable(self)
		if mt == nil then
			return true
		end
		return rawget(mt, "__metatable") == false
	end)

	-- Check 4: String dump detection
	self:AddCheck("dump", function(env)
		local dump = string.dump
		if dump then
			local ok, result = pcall(dump, function() end)
			if ok and type(result) == "string" and #result > 0 then
				-- dump available, suspicious but not fatal
			end
		end
		return true
	end)

	-- Check 5: Timing check
	self:AddCheck("timing", function(env)
		local clock = os and os.clock or tick
		if clock then
			local t1 = clock()
			local sum = 0
			for i = 1, 5000 do
				sum = (sum + i * 3) % 0x7FFFFFFF
			end
			local t2 = clock()
			if (t2 - t1) > 0.5 then
				return false
			end
		end
		return true
	end)

	return self
end

return AntiTamper
