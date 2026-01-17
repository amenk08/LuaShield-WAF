local _M = {}
function _M.load(config_path)
    if not config_path then
        return nil, "No config path provided"
    end
    

    local ok, config = pcall(dofile, config_path)
    if not ok then
        return nil, "Failed to load config: " .. tostring(config)
    end
    

    config = _M.validate(config)
    
    return config
end
function _M.validate(config)
    config = config or {}
    

    config.global = config.global or {}
    config.global.waf_enable = config.global.waf_enable ~= false
    config.global.mode = config.global.mode or "block"
    config.global.debug = config.global.debug or false
    config.global.fail_open = config.global.fail_open ~= false
    

    config.modules = config.modules or {}
    

    config.log = config.log or {}
    config.log.enable = config.log.enable ~= false
    config.log.path = config.log.path or "/var/log/waf/"
    config.log.level = config.log.level or "info"
    config.log.format = config.log.format or "json"
    

    config.response = config.response or {}
    config.response.block_code = config.response.block_code or 403
    config.response.block_message = config.response.block_message or "Request blocked by WAF"
    
    return config
end
function _M.get_base_path()

    local base = debug.getinfo(1, "S").source:match("@(.*/)")
    if base then
        return base:gsub("/lib/resty/waf/core/$", "")
    end
    return "/usr/local/openresty/waf"
end

return _M
