local _M = {
    name = "encoding_bypass",
    version = "0.1.0"
}

local codec = require "resty.waf.utils.codec"
local loader = require "resty.waf.rules.loader"
local matcher = require "resty.waf.rules.matcher"

local rules = {}
local default_patterns = {

    {
        id = "enc-001",
        name = "Double URL Encoding",
        description = "Detects double URL encoding bypass",
        pattern = "%25[0-9a-fA-F]{2}",
        operator = "regex",
        enabled = true,
        severity = "high"
    },

    {
        id = "enc-002",
        name = "Unicode Encoding",
        description = "Detects %uXXXX unicode encoding",
        pattern = "%u[0-9a-fA-F]{4}",
        operator = "regex",
        enabled = true,
        severity = "high"
    },

    {
        id = "enc-003",
        name = "Overlong UTF-8",
        description = "Detects overlong UTF-8 encoding bypass",
        pattern = "%c0%ae|%c1%9c|%c0%af",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },

    {
        id = "enc-004",
        name = "Null Byte Injection",
        description = "Detects null byte injection",
        pattern = "%00|\\x00|\\0",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },

    {
        id = "enc-005",
        name = "Mixed Case Encoding",
        description = "Detects mixed case URL encoding evasion",
        pattern = "%[0-9][a-f]|%[0-9][A-F]|%[a-f][0-9]|%[A-F][0-9]",
        operator = "regex",
        enabled = true,
        severity = "medium"
    },

    {
        id = "enc-006",
        name = "HTML Entity Script",
        description = "Detects HTML entity encoded script tags",
        pattern = "&#(?:60|x3c);|&#(?:62|x3e);|&lt;|&gt;",
        operator = "regex",
        enabled = true,
        severity = "high"
    },

    {
        id = "enc-007",
        name = "Hex Encoding",
        description = "Detects hex encoded characters",
        pattern = "\\\\x[0-9a-fA-F]{2}",
        operator = "regex",
        enabled = true,
        severity = "medium"
    },

    {
        id = "enc-008",
        name = "Invalid Percent Encoding",
        description = "Detects invalid percent encoding",
        pattern = "%(?![0-9a-fA-F]{2})[^\\s]",
        operator = "regex",
        enabled = true,
        severity = "medium"
    },

    {
        id = "enc-009",
        name = "Suspicious Base64",
        description = "Detects base64 encoded payloads in parameters",
        pattern = "(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        operator = "regex",
        enabled = false,
        severity = "low"
    },

    {
        id = "enc-010",
        name = "UTF-7 Encoding",
        description = "Detects UTF-7 encoding bypass",
        pattern = "\\+AD[wxy][-A-Za-z0-9+/]",
        operator = "regex",
        enabled = true,
        severity = "high"
    }
}
function _M.init(config, global_config)
    if config.rule_file then
        local loaded, err = loader.load_file(config.rule_file)
        if loaded then
            rules = loader.compile_rules(loaded)
            ngx.log(ngx.INFO, "Encoding Bypass: loaded ", #rules, " rules from file")
        else
            ngx.log(ngx.WARN, "Encoding Bypass: using default rules, file error: ", err)
            rules = loader.compile_rules(default_patterns)
        end
    else
        rules = loader.compile_rules(default_patterns)
        ngx.log(ngx.INFO, "Encoding Bypass: using ", #rules, " default rules")
    end
end
local function collect_targets(ctx, config)
    local targets = {}
    

    if config.check_uri ~= false then
        table.insert(targets, ctx.request_uri)
    end
    

    if config.check_args ~= false then
        for k, v in pairs(ctx.uri_args or {}) do
            if type(v) == "table" then
                for _, item in ipairs(v) do
                    table.insert(targets, item)
                end
            else
                table.insert(targets, v)
            end
        end
    end
    

    if config.check_body ~= false and ctx.body then
        table.insert(targets, ctx.body)
        for k, v in pairs(ctx.post_args or {}) do
            if type(v) == "table" then
                for _, item in ipairs(v) do
                    table.insert(targets, tostring(item))
                end
            else
                table.insert(targets, tostring(v))
            end
        end
    end
    

    if config.check_headers ~= false and ctx.headers then
        local check_headers = {"User-Agent", "Referer", "Cookie", "X-Forwarded-For"}
        for _, h in ipairs(check_headers) do
            if ctx.headers[h] then
                table.insert(targets, ctx.headers[h])
            end
        end
    end
    
    return targets
end
function _M.check(ctx, config)
    local targets = collect_targets(ctx, config)
    

    local result = matcher.match_any(rules, targets)
    if result.matched then
        return {
            blocked = true,
            attack_type = "Encoding Bypass",
            rule_id = result.rule.id,
            evidence = result.evidence,
            severity = result.rule.severity
        }
    end
    

    if config.deep_decode then
        for _, target in ipairs(targets) do
            if target and target ~= "" then
                local has_enc, enc_type = codec.has_encoding(target)
                if has_enc then
                    local decoded = codec.decode_all(target)
                    

                    if decoded ~= target then

                        local suspicious_patterns = {
                            "<script",
                            "javascript:",
                            "onerror",
                            "onclick",
                            "../",
                            "select.*from",
                            "union.*select",
                            "; *cat ",
                            "|.*sh"
                        }
                        
                        for _, pattern in ipairs(suspicious_patterns) do
                            if ngx.re.match(decoded:lower(), pattern, "joi") then
                                return {
                                    blocked = true,
                                    attack_type = "Encoding Bypass - " .. enc_type,
                                    rule_id = "enc-decode-" .. enc_type,
                                    evidence = "Encoded: " .. target:sub(1, 50) .. 
                                              " -> Decoded: " .. decoded:sub(1, 50),
                                    severity = "high"
                                }
                            end
                        end
                    end
                end
            end
        end
    end
    
    return { blocked = false }
end
function _M.get_decoded_values(ctx)
    local decoded = {}
    
    if ctx.request_uri then
        decoded.request_uri = codec.decode_all(ctx.request_uri)
    end
    
    decoded.uri_args = {}
    for k, v in pairs(ctx.uri_args or {}) do
        if type(v) == "table" then
            decoded.uri_args[k] = {}
            for i, item in ipairs(v) do
                decoded.uri_args[k][i] = codec.decode_all(item)
            end
        else
            decoded.uri_args[k] = codec.decode_all(v)
        end
    end
    
    if ctx.body then
        decoded.body = codec.decode_all(ctx.body)
    end
    
    return decoded
end

return _M
