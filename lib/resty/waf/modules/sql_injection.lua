local _M = {
    name = "sql_injection",
    version = "0.1.0"
}

local loader = require "resty.waf.rules.loader"
local matcher = require "resty.waf.rules.matcher"

local rules = {}
local default_patterns = {
    {
        id = "sqli-001",
        name = "Union Select",
        pattern = "(?i)(?:union[\\s\\/\\*]+(?:all|distinct|select))",
        operator = "regex",
        enabled = true,
        severity = "critical"
    },
    {
        id = "sqli-002",
        name = "SQL Comment",
        pattern = "(?:--|#|\\/\\*)",
        operator = "regex",
        enabled = true,
        severity = "medium"
    },
    {
        id = "sqli-003",
        name = "Boolean Injection",
        pattern = "(?i)(?:'|\")?\\s*(?:or|and)\\s+['\"]?\\d+['\"]?\\s*[=<>]+\\s*['\"]?\\d+",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "sqli-004",
        name = "SQL Functions",
        pattern = "(?i)(?:concat|char|substring|ascii|bin|hex|unhex|benchmark|sleep|load_file|into\\s+outfile)\\s*\\(",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "sqli-005",
        name = "SQL Keywords",
        pattern = "(?i)(?:select|insert|update|delete|drop|truncate|alter|create|exec|execute)\\s+",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "sqli-006",
        name = "Tautology",
        pattern = "(?i)['\"]\\s*(?:or|and)\\s*['\"]?[^'\"]+['\"]?\\s*=\\s*['\"]?[^'\"]+['\"]?",
        operator = "regex",
        enabled = true,
        severity = "high"
    },
    {
        id = "sqli-007",
        name = "Order By Injection",
        pattern = "(?i)order\\s+by\\s+\\d+",
        operator = "regex",
        enabled = true,
        severity = "medium"
    },
    {
        id = "sqli-008",
        name = "Information Schema",
        pattern = "(?i)information_schema|sysobjects|syscolumns|mysql\\.user",
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
            ngx.log(ngx.INFO, "SQL Injection: loaded ", #rules, " rules from file")
        else
            ngx.log(ngx.WARN, "SQL Injection: using default rules, file error: ", err)
            rules = loader.compile_rules(default_patterns)
        end
    else
        rules = loader.compile_rules(default_patterns)
        ngx.log(ngx.INFO, "SQL Injection: using ", #rules, " default rules")
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
            attack_type = "SQL Injection",
            rule_id = result.rule.id,
            evidence = result.evidence,
            severity = result.rule.severity
        }
    end
    
    return { blocked = false }
end

return _M
