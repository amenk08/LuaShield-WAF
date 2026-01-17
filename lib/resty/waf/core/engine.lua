local _M = {
    _VERSION = "0.1.0"
}
local mt = { __index = _M }

local request = require "resty.waf.core.request"
local response = require "resty.waf.core.response"
local logger = require "resty.waf.utils.logger"
local modules = {}
function _M.new(config)
    local self = {
        config = config,
        modules = {},
        logger = logger.new(config.log),
        ctx = nil
    }
    return setmetatable(self, mt)
end
function _M:init()
    local config = self.config
    
    if not config.global.waf_enable then
        ngx.log(ngx.WARN, "WAF is disabled by configuration")
        return true
    end
    

    local module_list = {
        { name = "ip_filter", path = "resty.waf.modules.ip_filter" },
        { name = "rate_limit", path = "resty.waf.modules.rate_limit" },
        { name = "encoding_bypass", path = "resty.waf.modules.encoding_bypass" },
        { name = "sql_injection", path = "resty.waf.modules.sql_injection" },
        { name = "xss", path = "resty.waf.modules.xss" },
        { name = "path_traversal", path = "resty.waf.modules.path_traversal" },
        { name = "cmd_injection", path = "resty.waf.modules.cmd_injection" },
    }
    
    for _, mod_info in ipairs(module_list) do
        local mod_config = config.modules[mod_info.name]
        if mod_config and mod_config.enable then
            local ok, mod = pcall(require, mod_info.path)
            if ok then
                if mod.init then
                    mod.init(mod_config, config)
                end
                table.insert(self.modules, {
                    name = mod_info.name,
                    module = mod,
                    config = mod_config
                })
                ngx.log(ngx.DEBUG, "Loaded module: ", mod_info.name)
            else
                ngx.log(ngx.WARN, "Failed to load module: ", mod_info.name, " - ", mod)
            end
        end
    end
    
    ngx.log(ngx.INFO, "WAF engine initialized with ", #self.modules, " modules")
    return true
end
function _M:init_worker()

    for _, mod_entry in ipairs(self.modules) do
        if mod_entry.module.init_worker then
            mod_entry.module.init_worker(mod_entry.config)
        end
    end
end
function _M:exec()
    local config = self.config
    

    if not config.global.waf_enable then
        return
    end
    

    if config.global.mode == "bypass" then
        return
    end
    

    local ctx, err = request.build_context()
    if not ctx then
        ngx.log(ngx.ERR, "Failed to build request context: ", err)
        if not config.global.fail_open then
            return ngx.exit(500)
        end
        return
    end
    

    ngx.ctx.waf = ctx
    self.ctx = ctx
    

    local ok, err = pcall(function()
        self:do_check(ctx)
    end)
    
    if not ok then
        ngx.log(ngx.ERR, "WAF check error: ", err)
        if not config.global.fail_open then
            return ngx.exit(500)
        end
    end
end
function _M:do_check(ctx)
    local config = self.config
    

    for _, mod_entry in ipairs(self.modules) do
        local result = mod_entry.module.check(ctx, mod_entry.config)
        
        if result and result.blocked then

            ctx.is_attack = true
            ctx.attack_type = result.attack_type or mod_entry.name
            ctx.rule_id = result.rule_id
            ctx.evidence = result.evidence
            ctx.action = result.action
            

            self.logger:log_attack(ctx, result)
            

            if config.global.mode == "block" then
                return self:handle_block(ctx, result)
            end

        end
    end
end
function _M:handle_block(ctx, result)
    local config = self.config
    

    if result.action == "captcha" and result.redirect_url then
        return ngx.redirect(result.redirect_url)
    end
    

    if result.action == "ban" then
        local code = result.response_code or config.response.block_code
        ngx.status = code
        ngx.header["Content-Type"] = "text/html; charset=utf-8"
        ngx.header["Retry-After"] = result.remaining_time or result.ban_duration
        
        local body = result.message or config.response.block_message
        if result.remaining_time then
            body = body .. string.format(" (Remaining: %d seconds)", math.ceil(result.remaining_time))
        end
        
        ngx.say(body)
        return ngx.exit(code)
    end
    

    return response.block(config.response)
end
function _M:log()
    local ctx = ngx.ctx.waf
    if ctx and ctx.is_attack then

    end
end

return _M
