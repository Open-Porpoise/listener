#!/usr/bin/env lua
local string = require("string")

JSON = assert(loadfile "JSON.lua")() -- one-time load of the routines

function save_file(file_name, content)
	local fd = io.open(file_name, "w+")
	fd:write(content)                                                                                                                                                                                               
end 


os.execute("wget http://xman2.pt.xiaomi.com/api/list_subnet -O ip_list.json")
local f = io.open("ip_list.json", "r")
local t = f:read("*all")
local j = JSON:decode(t)
f:close()

local fd = io.open("ip_list.txt", "w")
for k, v in pairs(j) do
	--[[
	--subnet_id       749
	--mask    24
	--remark  lan:c3
	--subnet  10.108.4.0
	--isp     内网
	--nodegroup
	--site    lan
	]]
	--if v[isp] ~= "\u5185\u7f51" then 
	if v['isp'] ~= '内网'  and  v['subnet'] ~= nil then
		fd:write(string.format("%s/%s\n", v['subnet'] and v['subnet']  or "", 
		v['mask'] and v['mask'] or "32"))
		--[[
		fd:write(string.format("%s/%s \"%s\" \"%s\" \"%s\" \"%s\"\n", 
		v['subnet'] and v['subnet']  or "", 
		v['mask'] and v['mask'] or "32",
		v['name'] and v['name'] or "NA",
		v['remark'] and v['remark'] or "NA",
		v['site'] and v['site'] or "NA",
		v['isp'] and v['isp'] or "NA"))
		]]
	end
end
fd:close()
