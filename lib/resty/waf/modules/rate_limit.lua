local _M = {
    name = "rate_limit",
    version = "0.2.0"
}

local ip_utils = require "resty.waf.utils.ip"

local config_cache = nil
function _M.init(config, global_config)
    config_cache = config
    ngx.log(ngx.INFO, "Rate Limit module initialized")
end
local function check_ban(key)
    local shared_ban = ngx.shared.waf_ban
    if not shared_ban then
        return false, 0
    end
    
    local ban_until = shared_ban:get("ban:" .. key)
    if ban_until then
        local remaining = ban_until - ngx.now()
        if remaining > 0 then
            return true, remaining
        else
            shared_ban:delete("ban:" .. key)
        end
    end
    return false, 0
end
local function add_ban(key, duration)
    local shared_ban = ngx.shared.waf_ban
    if not shared_ban then
        ngx.log(ngx.ERR, "waf_ban shared dict not configured")
        return
    end
    
    local ban_until = ngx.now() + duration
    shared_ban:set("ban:" .. key, ban_until, duration + 60)
    ngx.log(ngx.WARN, "[WAF] IP banned: ", key, " for ", duration, " seconds")
end
local function check_captcha_verified(config)
    if not config.captcha then
        return false
    end
    
    local cookie_name = config.captcha.cookie_name or "waf_verified"
    local cookie = ngx.var["cookie_" .. cookie_name]
    
    if cookie then

        local secret = config.captcha.secret_key or "default-secret"
        local expected = ngx.encode_base64(ngx.hmac_sha1(secret, ngx.var.remote_addr))
        return cookie == expected
    end
    
    return false
end
local function token_bucket_check(key, rate, burst, ttl)
    local shared_dict = ngx.shared.waf_limit
    if not shared_dict then
        ngx.log(ngx.ERR, "waf_limit shared dict not configured")
        return { allowed = true }
    end
    
    local now = ngx.now()
    local tokens_key = key .. ":tokens"
    local time_key = key .. ":time"
    
    local tokens = shared_dict:get(tokens_key)
    local last_time = shared_dict:get(time_key)
    

    local tokens_per_second = rate / ttl
    

    if not tokens then
        shared_dict:set(tokens_key, burst - 1, ttl)
        shared_dict:set(time_key, now, ttl)
        return { allowed = true, remaining = burst - 1 }
    end
    

    local elapsed = now - (last_time or now)
    local new_tokens = math.min(burst, tokens + elapsed * tokens_per_second)
    
    if new_tokens >= 1 then
        shared_dict:set(tokens_key, new_tokens - 1, ttl)
        shared_dict:set(time_key, now, ttl)
        return { allowed = true, remaining = new_tokens - 1 }
    end
    
    return {
        allowed = false,
        remaining = 0,
        retry_after = (1 - new_tokens) / tokens_per_second
    }
end
local function sliding_window_check(key, rate, window_size)
    local shared_dict = ngx.shared.waf_limit
    if not shared_dict then
        return { allowed = true }
    end
    
    local count_key = key .. ":count"
    local count, err = shared_dict:incr(count_key, 1, 0, window_size)
    
    if not count then
        ngx.log(ngx.ERR, "Rate limit incr error: ", err)
        return { allowed = true }
    end
    
    if count <= rate then
        return { allowed = true, remaining = rate - count }
    end
    
    return { allowed = false, remaining = 0 }
end
local function build_key(ip, ctx, key_type)
    if key_type == "ip" then
        return "rl:" .. ip
    elseif key_type == "ip+uri" then
        return "rl:" .. ip .. ":" .. ctx.uri
    elseif key_type == "ip+user_agent" then
        return "rl:" .. ip .. ":" .. ngx.md5(ctx.user_agent or "")
    else
        return "rl:" .. ip
    end
end
local function is_whitelisted(ip, ctx, whitelist)
    if not whitelist then
        return false
    end
    

    if whitelist.ips then
        for _, white_ip in ipairs(whitelist.ips) do
            if ip_utils.match_cidr(ip, white_ip) then
                return true
            end
        end
    end
    

    if whitelist.uris then
        for _, white_uri in ipairs(whitelist.uris) do
            if ctx.uri:find(white_uri, 1, true) == 1 then
                return true
            end
        end
    end
    

    if whitelist.extensions then
        local uri_lower = ctx.uri:lower()
        for _, ext in ipairs(whitelist.extensions) do
            if uri_lower:match("%." .. ext .. "$") or uri_lower:match("%." .. ext .. "?") then
                return true
            end
        end
    end
    

    if whitelist.user_agents and ctx.user_agent then
        for _, white_ua in ipairs(whitelist.user_agents) do
            if ctx.user_agent:find(white_ua, 1, true) then
                return true
            end
        end
    end
    
    return false
end
function _M.check(ctx, config)
    local client_ip = ctx.client_ip
    

    if is_whitelisted(client_ip, ctx, config.whitelist) then
        return { blocked = false, whitelisted = true }
    end
    

    local banned, remaining_time = check_ban(client_ip)
    if banned then
        return {
            blocked = true,
            action = "ban",
            attack_type = "Rate Limit Ban",
            remaining_time = remaining_time,
            message = config.ban and config.ban.response_body or "IP banned",
            response_code = config.ban and config.ban.response_code or 403
        }
    end
    

    if check_captcha_verified(config) then
        return { blocked = false, verified = true }
    end
    

    local rate_key = build_key(client_ip, ctx, config.key_type)
    

    for i, threshold in ipairs(config.thresholds or {}) do
        local result
        
        if config.algorithm == "sliding_window" then
            result = sliding_window_check(
                rate_key .. ":" .. threshold.name,
                threshold.rate,
                threshold.ttl
            )
        else
            result = token_bucket_check(
                rate_key .. ":" .. threshold.name,
                threshold.rate,
                threshold.burst,
                threshold.ttl
            )
        end
        
        if not result.allowed then
            if threshold.action == "captcha" then
                local redirect_url = config.captcha and config.captcha.redirect_url or "/waf/captcha"
                return {
                    blocked = true,
                    action = "captcha",
                    attack_type = "Rate Limit Exceeded",
                    redirect_url = redirect_url .. "?return_url=" .. ngx.escape_uri(ctx.request_uri),
                    level = i
                }
            elseif threshold.action == "ban" then
                add_ban(client_ip, threshold.ban_duration)
                return {
                    blocked = true,
                    action = "ban",
                    attack_type = "Rate Limit Ban",
                    ban_duration = threshold.ban_duration,
                    message = config.ban and config.ban.response_body,
                    response_code = config.ban and config.ban.response_code or 403,
                    level = i
                }
            elseif threshold.action == "delay" then
                ngx.sleep(threshold.delay or 1)
                return { blocked = false, delayed = true }
            else
                return {
                    blocked = true,
                    action = "block",
                    attack_type = "Rate Limit Exceeded",
                    level = i
                }
            end
        end
    end
    
    return { blocked = false }
end

return _M
