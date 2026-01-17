local _M = {
    name = "xss",
    version = "0.1.0"
}

local loader = require "resty.waf.rules.loader"
local matcher = require "resty.waf.rules.matcher"

local rules = {}
local default_patterns = {
    {
        id = "xss-001",
        name = "Script Tag",
        pattern = "(?i)<script[^>]*>[\\s\\S]*?</script>",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },
    {
        id = "xss-002",
        name = "Script Tag Open",
        pattern = "(?i)<script[^>]*>",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },
    {
        id = "xss-003",
        name = "Event Handlers",
        pattern = "(?i)\\bon(?:click|load|error|mouseover|mouseout|focus|blur|change|submit|keydown|keyup|keypress|dblclick|mousedown|mouseup|mousemove|contextmenu|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|abort|canplay|ended|input|invalid|pause|play|playing|progress|ratechange|reset|scroll|seeked|seeking|select|show|stalled|suspend|timeupdate|toggle|volumechange|waiting)\\s*=",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "xss-004",
        name = "JavaScript Protocol",
        pattern = "(?i)javascript:[^\"']*",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "xss-005",
        name = "Data URI",
        pattern = "(?i)data:[^,]*;base64,",
        operator = "regex",
        enabled = true,
        severity = "medium"
    },
    {
        id = "xss-006",
        name = "VBScript Protocol",
        pattern = "(?i)vbscript:",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "xss-007",
        name = "Expression CSS",
        pattern = "(?i)expression\\s*\\(",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "xss-008",
        name = "Iframe Injection",
        pattern = "(?i)<iframe[^>]*>",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "xss-009",
        name = "Object/Embed Tag",
        pattern = "(?i)<(?:object|embed|applet)[^>]*>",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "xss-010",
        name = "SVG onload",
        pattern = "(?i)<svg[^>]*onload[^>]*>",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "xss-011",
        name = "IMG onerror",
        pattern = "(?i)<img[^>]*onerror[^>]*>",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "xss-012",
        name = "Body onload",
        pattern = "(?i)<body[^>]*onload[^>]*>",
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
            ngx.log(ngx.INFO, "XSS: loaded ", #rules, " rules from file")
        else
            ngx.log(ngx.WARN, "XSS: using default rules, file error: ", err)
            rules = loader.compile_rules(default_patterns)
        end
    else
        rules = loader.compile_rules(default_patterns)
        ngx.log(ngx.INFO, "XSS: using ", #rules, " default rules")
    end
end
function _M.check(ctx, config)
    local targets = {}
    
    if config.check_uri ~= false then
        table.insert(targets, ctx.uri)
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
    
    if config.check_cookie ~= false then
        for k, v in pairs(ctx.cookies or {}) do
            table.insert(targets, v)
        end
    end
    
    local result = matcher.match_any(rules, targets)
    
    if result.matched then
        return {
            blocked = true,
            attack_type = "XSS",
            rule_id = result.rule.id,
            evidence = result.evidence,
            severity = result.rule.severity
        }
    end
    
    return { blocked = false }
end

return _M
