local _M = {}
local mt = { __index = _M }

local cjson = require "cjson.safe"

local log_levels = {
    debug = ngx.DEBUG,
    info = ngx.INFO,
    warn = ngx.WARN,
    error = ngx.ERR
}
function _M.new(config)
    local self = {
        enable = config.enable ~= false,
        path = config.path or "/var/log/waf/",
        level = config.level or "info",
        format = config.format or "json"
    }
    return setmetatable(self, mt)
end
local function build_log_entry(ctx, result)
    return {
        timestamp = ngx.localtime(),
        request_id = ctx.request_id,
        client_ip = ctx.client_ip,
        method = ctx.method,
        uri = ctx.uri,
        host = ctx.host,
        user_agent = ctx.user_agent,
        referer = ctx.referer,
        attack_type = result.attack_type or ctx.attack_type,
        rule_id = result.rule_id or ctx.rule_id,
        evidence = result.evidence or ctx.evidence,
        action = result.action or "block",
        score = result.score or ctx.attack_score
    }
end
function _M:log_attack(ctx, result)
    if not self.enable then
        return
    end
    
    local entry = build_log_entry(ctx, result)
    entry.level = "warn"
    entry.type = "attack"
    

    ngx.log(ngx.WARN, "[WAF] ", cjson.encode(entry))
    

    if self.path then
        local log_path = self.path
        local log_entry = cjson.encode(entry)
        
        ngx.timer.at(0, function(premature)
            if premature then return end
            

            local date_str = os.date("%Y-%m-%d")
            local log_file = log_path .. "attack_" .. date_str .. ".log"
            
            local file, err = io.open(log_file, "a")
            if file then
                file:write(log_entry .. "\n")
                file:close()
            else
                ngx.log(ngx.ERR, "[WAF] Failed to write log file: ", log_file, " error: ", err)
            end
        end)
    end
end
function _M:log(level, message, data)
    if not self.enable then
        return
    end
    
    local ngx_level = log_levels[level] or ngx.INFO
    
    if data then
        ngx.log(ngx_level, "[WAF] ", message, " ", cjson.encode(data))
    else
        ngx.log(ngx_level, "[WAF] ", message)
    end
end
function _M:debug(message, data)
    self:log("debug", message, data)
end
function _M:info(message, data)
    self:log("info", message, data)
end
function _M:warn(message, data)
    self:log("warn", message, data)
end
function _M:error(message, data)
    self:log("error", message, data)
end

return _M
