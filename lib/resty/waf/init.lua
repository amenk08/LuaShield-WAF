local _M = {
    _VERSION = "0.1.0",
    _NAME = "LuaShield WAF"
}

local engine = require "resty.waf.core.engine"
local config_loader = require "resty.waf.core.config"

local waf_engine = nil
function _M.init(config_path)
    local config, err = config_loader.load(config_path)
    if not config then
        ngx.log(ngx.ERR, "Failed to load WAF config: ", err)
        return false
    end
    
    waf_engine = engine.new(config)
    local ok, err = waf_engine:init()
    if not ok then
        ngx.log(ngx.ERR, "Failed to initialize WAF engine: ", err)
        return false
    end
    
    ngx.log(ngx.INFO, _M._NAME, " v", _M._VERSION, " initialized")
    return true
end
function _M.init_worker()
    if waf_engine then
        waf_engine:init_worker()
    end
end
function _M.exec()
    if not waf_engine then
        ngx.log(ngx.ERR, "WAF engine not initialized")
        return
    end
    
    waf_engine:exec()
end
function _M.log()
    if waf_engine then
        waf_engine:log()
    end
end
function _M.version()
    return _M._VERSION
end

return _M
