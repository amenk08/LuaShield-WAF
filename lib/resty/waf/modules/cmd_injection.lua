local _M = {
    name = "cmd_injection",
    version = "0.1.0"
}

local loader = require "resty.waf.rules.loader"
local matcher = require "resty.waf.rules.matcher"

local rules = {}
local default_patterns = {
    {
        id = "cmd-001",
        name = "Command Separator",
        pattern = "(?:[;|`]|\\$\\(|&&|\\|\\|)",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },
    {
        id = "cmd-002",
        name = "Backtick Execution",
        pattern = "`[^`]+`",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },
    {
        id = "cmd-003",
        name = "Command Substitution",
        pattern = "\\$\\([^)]+\\)",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },
    {
        id = "cmd-004",
        name = "Dangerous Commands",
        pattern = "(?i)(?:(?:^|[;&|`])\\s*(?:cat|ls|dir|rm|mv|cp|wget|curl|nc|netcat|bash|sh|zsh|csh|python|perl|ruby|php|node)\\s)",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "cmd-005",
        name = "System Commands",
        pattern = "(?i)(?:/bin/(?:bash|sh|cat|ls|rm)|/usr/bin/(?:wget|curl|id|whoami)|cmd\\.exe|powershell)",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },
    {
        id = "cmd-006",
        name = "Environment Variable",
        pattern = "\\$(?:IFS|PATH|HOME|USER|SHELL)",
        operator = "regex",
        enabled = true,
        severity = "medium"
    },
    {
        id = "cmd-007",
        name = "Reverse Shell",
        pattern = "(?i)(?:bash\\s+-i|nc\\s+-e|/dev/tcp/|mkfifo|mknod)",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },
    {
        id = "cmd-008",
        name = "Encoded Commands",
        pattern = "(?i)(?:base64\\s+-d|eval\\s+|exec\\s+)",
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
            ngx.log(ngx.INFO, "Command Injection: loaded ", #rules, " rules from file")
        else
            ngx.log(ngx.WARN, "Command Injection: using default rules, file error: ", err)
            rules = loader.compile_rules(default_patterns)
        end
    else
        rules = loader.compile_rules(default_patterns)
        ngx.log(ngx.INFO, "Command Injection: using ", #rules, " default rules")
    end
end
function _M.check(ctx, config)
    local targets = {}
    

    for k, v in pairs(ctx.uri_args or {}) do
        if type(v) == "table" then
            for _, item in ipairs(v) do
                table.insert(targets, item)
            end
        else
            table.insert(targets, v)
        end
    end
    

    if ctx.body then
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
    

    if ctx.headers then
        local check_headers = {"User-Agent", "Referer", "X-Forwarded-For"}
        for _, h in ipairs(check_headers) do
            if ctx.headers[h] then
                table.insert(targets, ctx.headers[h])
            end
        end
    end
    
    local result = matcher.match_any(rules, targets)
    
    if result.matched then
        return {
            blocked = true,
            attack_type = "Command Injection",
            rule_id = result.rule.id,
            evidence = result.evidence,
            severity = result.rule.severity
        }
    end
    
    return { blocked = false }
end

return _M
