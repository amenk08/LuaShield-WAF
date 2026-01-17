local _M = {
    name = "ip_filter",
    version = "0.1.0"
}

local ip_utils = require "resty.waf.utils.ip"

local whitelist = {}
local blacklist = {}
local function load_ip_file(filepath)
    local list = {}
    local file = io.open(filepath, "r")
    
    if not file then
        ngx.log(ngx.WARN, "IP list file not found: ", filepath)
        return list
    end
    
    for line in file:lines() do

        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and not line:match("^#") then
            table.insert(list, line)
        end
    end
    
    file:close()
    ngx.log(ngx.DEBUG, "Loaded ", #list, " IPs from ", filepath)
    return list
end
function _M.init(config, global_config)
    if config.whitelist_file then
        whitelist = load_ip_file(config.whitelist_file)
    end
    
    if config.blacklist_file then
        blacklist = load_ip_file(config.blacklist_file)
    end
    
    ngx.log(ngx.INFO, "IP Filter initialized: ", #whitelist, " whitelist, ", #blacklist, " blacklist")
end
function _M.check(ctx, config)
    local client_ip = ctx.client_ip
    

    if #whitelist > 0 and ip_utils.in_cidrs(client_ip, whitelist) then
        return {
            blocked = false,
            whitelisted = true
        }
    end
    

    if #blacklist > 0 and ip_utils.in_cidrs(client_ip, blacklist) then
        return {
            blocked = true,
            attack_type = "IP Blacklist",
            rule_id = "ip-blacklist",
            evidence = client_ip
        }
    end
    
    return { blocked = false }
end
function _M.add_to_blacklist(ip)
    table.insert(blacklist, ip)
end
function _M.add_to_whitelist(ip)
    table.insert(whitelist, ip)
end

return _M
