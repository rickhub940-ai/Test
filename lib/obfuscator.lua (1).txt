--[[
  RobloxVMObf Client Library v2.0
  Usage:
    local Obf = require(path.to.Obfuscator)
    Obf.API_URL = "https://your-project.vercel.app/api/obfuscate"
    local protected = Obf:Obfuscate("local a = 1 print(a)")
    print(protected)
--]]

local HttpService = game:GetService("HttpService")
local Obfuscator = {}
Obfuscator.__index = Obfuscator

function Obfuscator.new(apiUrl)
	local self = setmetatable({}, Obfuscator)
	self.API_URL = apiUrl or "https://your-project.vercel.app/api/obfuscate"
	self.RetryCount = 3
	self.Timeout = 30
	return self
end

function Obfuscator:SetRetry(count)
	self.RetryCount = count or 3
	return self
end

function Obfuscator:SetTimeout(sec)
	self.Timeout = sec or 30
	return self
end

function Obfuscator:Obfuscate(sourceCode)
	assert(type(sourceCode) == "string", "[RobloxVMObf] sourceCode must be a string")

	local payload = HttpService:JSONEncode({
		code = sourceCode,
		client = "roblox",
		version = "2.0.0"
	})

	local lastError = nil
	for attempt = 1, self.RetryCount do
		local success, result = pcall(function()
			return HttpService:PostAsync(
				self.API_URL,
				payload,
				Enum.HttpContentType.ApplicationJson,
				false
			)
		end)

		if success then
			local decoded = HttpService:JSONDecode(result)
			if decoded.ok and decoded.result then
				return decoded.result
			else
				error("[RobloxVMObf] API returned error: " .. tostring(decoded.error or "unknown"))
			end
		else
			lastError = result
			if attempt < self.RetryCount then
				wait(math.min(2 ^ attempt, 8))
			end
		end
	end

	error("[RobloxVMObf] All retries failed. Last error: " .. tostring(lastError))
end

function Obfuscator:ObfuscateAndLoad(sourceCode)
	local code = self:Obfuscate(sourceCode)
	local fn, err = loadstring(code)
	if not fn then
		error("[RobloxVMObf] Load failed: " .. tostring(err))
	end
	return fn
end

return Obfuscator
